"""
Caching System for API Results

Provides caching functionality to reduce API requests and improve performance.
Supports both in-memory and persistent disk caching with TTL (Time To Live).
"""

import json
import sqlite3
import hashlib
import time
import os
from typing import Dict, Any, Optional, Union
from pathlib import Path
import logging
import threading
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages caching for API results with TTL support."""
    
    def __init__(self, cache_dir: str = ".cache", default_ttl: int = 3600):
        """
        Initialize cache manager.
        
        Args:
            cache_dir: Directory to store cache files
            default_ttl: Default TTL in seconds (1 hour)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.default_ttl = default_ttl
        self.memory_cache = {}
        self.cache_lock = threading.RLock()
        
        # Initialize SQLite database for persistent caching
        self.db_path = self.cache_dir / "api_cache.db"
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize SQLite database for caching."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache_entries (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        ttl INTEGER NOT NULL,
                        api_provider TEXT,
                        query_type TEXT
                    )
                """)
                
                # Create index for faster lookups
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp_ttl 
                    ON cache_entries(timestamp, ttl)
                """)
                
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to initialize cache database: {e}")
    
    def _generate_cache_key(self, provider: str, endpoint: str, params: Dict[str, Any]) -> str:
        """
        Generate a unique cache key based on provider, endpoint, and parameters.
        
        Args:
            provider: API provider name
            endpoint: API endpoint
            params: Request parameters
            
        Returns:
            Unique cache key
        """
        # Create a deterministic string from parameters
        param_str = json.dumps(params, sort_keys=True)
        key_data = f"{provider}:{endpoint}:{param_str}"
        
        # Generate SHA256 hash for consistent key length
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def get(self, provider: str, endpoint: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get cached result if available and not expired.
        
        Args:
            provider: API provider name
            endpoint: API endpoint
            params: Request parameters
            
        Returns:
            Cached result or None if not found/expired
        """
        cache_key = self._generate_cache_key(provider, endpoint, params)
        
        with self.cache_lock:
            # Check memory cache first
            if cache_key in self.memory_cache:
                entry = self.memory_cache[cache_key]
                if self._is_valid_entry(entry):
                    logger.debug(f"Cache hit (memory): {provider}:{endpoint}")
                    return entry['value']
                else:
                    del self.memory_cache[cache_key]
            
            # Check persistent cache
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(
                        "SELECT value, timestamp, ttl FROM cache_entries WHERE key = ?",
                        (cache_key,)
                    )
                    row = cursor.fetchone()
                    
                    if row:
                        value_json, timestamp, ttl = row
                        entry = {
                            'value': json.loads(value_json),
                            'timestamp': timestamp,
                            'ttl': ttl
                        }
                        
                        if self._is_valid_entry(entry):
                            # Load into memory cache for faster access
                            self.memory_cache[cache_key] = entry
                            logger.debug(f"Cache hit (disk): {provider}:{endpoint}")
                            return entry['value']
                        else:
                            # Remove expired entry
                            conn.execute("DELETE FROM cache_entries WHERE key = ?", (cache_key,))
                            conn.commit()
            
            except Exception as e:
                logger.error(f"Error retrieving from cache: {e}")
        
        logger.debug(f"Cache miss: {provider}:{endpoint}")
        return None
    
    def put(self, provider: str, endpoint: str, params: Dict[str, Any], 
            value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """
        Store result in cache.
        
        Args:
            provider: API provider name
            endpoint: API endpoint
            params: Request parameters
            value: Result to cache
            ttl: Time to live in seconds (uses default if None)
        """
        if ttl is None:
            ttl = self.default_ttl
        
        cache_key = self._generate_cache_key(provider, endpoint, params)
        current_time = time.time()
        
        entry = {
            'value': value,
            'timestamp': current_time,
            'ttl': ttl
        }
        
        with self.cache_lock:
            # Store in memory cache
            self.memory_cache[cache_key] = entry
            
            # Store in persistent cache
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        INSERT OR REPLACE INTO cache_entries 
                        (key, value, timestamp, ttl, api_provider, query_type)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        cache_key,
                        json.dumps(value),
                        current_time,
                        ttl,
                        provider,
                        endpoint
                    ))
                    conn.commit()
                    
                logger.debug(f"Cached result: {provider}:{endpoint}")
            
            except Exception as e:
                logger.error(f"Error storing in cache: {e}")
    
    def _is_valid_entry(self, entry: Dict[str, Any]) -> bool:
        """Check if cache entry is still valid (not expired)."""
        current_time = time.time()
        expiry_time = entry['timestamp'] + entry['ttl']
        return current_time < expiry_time
    
    def invalidate(self, provider: str, endpoint: str, params: Dict[str, Any]) -> None:
        """
        Invalidate a specific cache entry.
        
        Args:
            provider: API provider name
            endpoint: API endpoint
            params: Request parameters
        """
        cache_key = self._generate_cache_key(provider, endpoint, params)
        
        with self.cache_lock:
            # Remove from memory cache
            if cache_key in self.memory_cache:
                del self.memory_cache[cache_key]
            
            # Remove from persistent cache
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("DELETE FROM cache_entries WHERE key = ?", (cache_key,))
                    conn.commit()
                    
                logger.debug(f"Invalidated cache entry: {provider}:{endpoint}")
            
            except Exception as e:
                logger.error(f"Error invalidating cache: {e}")
    
    def clear_expired(self) -> int:
        """
        Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        current_time = time.time()
        removed_count = 0
        
        with self.cache_lock:
            # Clear from memory cache
            expired_keys = []
            for key, entry in self.memory_cache.items():
                if not self._is_valid_entry(entry):
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.memory_cache[key]
                removed_count += 1
            
            # Clear from persistent cache
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute(
                        "DELETE FROM cache_entries WHERE timestamp + ttl < ?",
                        (current_time,)
                    )
                    removed_count += cursor.rowcount
                    conn.commit()
                    
                logger.info(f"Removed {removed_count} expired cache entries")
            
            except Exception as e:
                logger.error(f"Error clearing expired cache entries: {e}")
        
        return removed_count
    
    def clear_all(self) -> None:
        """Clear all cache entries."""
        with self.cache_lock:
            # Clear memory cache
            self.memory_cache.clear()
            
            # Clear persistent cache
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("DELETE FROM cache_entries")
                    conn.commit()
                    
                logger.info("Cleared all cache entries")
            
            except Exception as e:
                logger.error(f"Error clearing cache: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        stats = {
            'memory_entries': len(self.memory_cache),
            'disk_entries': 0,
            'total_size_mb': 0,
            'expired_entries': 0,
            'providers': {}
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Get total entries
                cursor = conn.execute("SELECT COUNT(*) FROM cache_entries")
                stats['disk_entries'] = cursor.fetchone()[0]
                
                # Get database size
                stats['total_size_mb'] = os.path.getsize(self.db_path) / (1024 * 1024)
                
                # Get expired entries count
                current_time = time.time()
                cursor = conn.execute(
                    "SELECT COUNT(*) FROM cache_entries WHERE timestamp + ttl < ?",
                    (current_time,)
                )
                stats['expired_entries'] = cursor.fetchone()[0]
                
                # Get provider statistics
                cursor = conn.execute("""
                    SELECT api_provider, COUNT(*) as count 
                    FROM cache_entries 
                    GROUP BY api_provider
                """)
                for provider, count in cursor.fetchall():
                    stats['providers'][provider] = count
        
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
        
        return stats


# Global cache instance
_cache_manager = None


def get_cache_manager() -> CacheManager:
    """Get the global cache manager instance."""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager


def cached_api_call(provider: str, endpoint: str, ttl: Optional[int] = None):
    """
    Decorator for caching API calls.
    
    Args:
        provider: API provider name
        endpoint: API endpoint
        ttl: Cache TTL in seconds
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            cache = get_cache_manager()
            
            # Create cache key from function arguments
            cache_params = {
                'args': args,
                'kwargs': kwargs
            }
            
            # Check cache first
            cached_result = cache.get(provider, endpoint, cache_params)
            if cached_result is not None:
                return cached_result
            
            # Call original function
            result = await func(*args, **kwargs)
            
            # Cache the result if it's not an error
            if isinstance(result, dict) and 'error' not in result:
                cache.put(provider, endpoint, cache_params, result, ttl)
            
            return result
        
        return wrapper
    return decorator 


class Cache:
    """
    Simple cache interface for testing and basic usage.
    Wraps the CacheManager for backwards compatibility.
    """
    
    def __init__(self, cache_file: Optional[str] = None):
        """
        Initialize cache.
        
        Args:
            cache_file: Path to cache file (optional)
        """
        if cache_file:
            cache_dir = str(Path(cache_file).parent)
        else:
            cache_dir = ".cache"
        
        self._manager = CacheManager(cache_dir=cache_dir)
        self._default_provider = "default"
        self._default_endpoint = "cache"
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        if key is None:
            return None
        
        params = {"key": key}
        result = self._manager.get(self._default_provider, self._default_endpoint, params)
        return result.get('value') if result else None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            
        Returns:
            True if successful
        """
        if key is None:
            return False
        
        params = {"key": key}
        cache_value = {"value": value}
        
        try:
            self._manager.put(self._default_provider, self._default_endpoint, params, cache_value, ttl)
            return True
        except Exception:
            return False
    
    def delete(self, key: str) -> bool:
        """
        Delete value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if successful
        """
        if key is None:
            return False
        
        params = {"key": key}
        try:
            self._manager.invalidate(self._default_provider, self._default_endpoint, params)
            return True
        except Exception:
            return False
    
    def clear(self) -> None:
        """Clear all cached values."""
        try:
            self._manager.clear_all()
        except Exception:
            pass 