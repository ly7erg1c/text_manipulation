"""
Archive Processor

Provides functionality to process ZIP, RAR, and other archive files
for text extraction and analysis.
"""

import zipfile
import rarfile
import tarfile
import gzip
import bz2
import lzma
import os
import tempfile
import shutil
from typing import Dict, List, Any, Optional, Generator, Tuple
from pathlib import Path
import logging
import mimetypes
from io import BytesIO, StringIO

logger = logging.getLogger(__name__)


class ArchiveProcessor:
    """Processes various archive formats for text extraction."""
    
    # Supported archive extensions
    SUPPORTED_ARCHIVES = {
        '.zip': 'zip',
        '.rar': 'rar',
        '.tar': 'tar',
        '.tar.gz': 'tar.gz',
        '.tgz': 'tar.gz',
        '.tar.bz2': 'tar.bz2',
        '.tbz2': 'tar.bz2',
        '.tar.xz': 'tar.xz',
        '.txz': 'tar.xz',
        '.gz': 'gzip',
        '.bz2': 'bzip2',
        '.xz': 'xz',
        '.7z': '7zip'
    }
    
    # Text file extensions to extract
    TEXT_EXTENSIONS = {
        '.txt', '.log', '.md', '.rst', '.csv', '.json', '.xml', '.html',
        '.htm', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.py', '.js',
        '.c', '.cpp', '.h', '.hpp', '.java', '.cs', '.php', '.rb', '.go',
        '.rs', '.swift', '.kt', '.scala', '.pl', '.ps1', '.sh', '.bat',
        '.cmd', '.sql', '.r', '.m', '.tex', '.rtf', '.properties'
    }
    
    # Maximum file size to process (in bytes) - 10MB default
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    # Maximum number of files to extract from an archive
    MAX_FILES_PER_ARCHIVE = 100
    
    def __init__(self, max_file_size: int = None, max_files: int = None):
        """
        Initialize archive processor.
        
        Args:
            max_file_size: Maximum file size to process in bytes
            max_files: Maximum number of files to extract per archive
        """
        self.max_file_size = max_file_size or self.MAX_FILE_SIZE
        self.max_files = max_files or self.MAX_FILES_PER_ARCHIVE
    
    def is_supported_archive(self, file_path: str) -> bool:
        """
        Check if file is a supported archive format.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if supported, False otherwise
        """
        file_path = file_path.lower()
        
        # Check for compound extensions first (e.g., .tar.gz)
        for ext in ['.tar.gz', '.tar.bz2', '.tar.xz']:
            if file_path.endswith(ext):
                return True
        
        # Check single extensions
        for ext in self.SUPPORTED_ARCHIVES:
            if file_path.endswith(ext):
                return True
        
        return False
    
    def extract_text_from_archive(self, archive_path: str) -> Dict[str, Any]:
        """
        Extract text content from archive files.
        
        Args:
            archive_path: Path to the archive file
            
        Returns:
            Dictionary containing extracted text and metadata
        """
        result = {
            'archive_path': archive_path,
            'archive_type': self._get_archive_type(archive_path),
            'files_processed': 0,
            'files_skipped': 0,
            'total_text_length': 0,
            'extracted_files': [],
            'errors': [],
            'text_content': {}
        }
        
        try:
            if not self.is_supported_archive(archive_path):
                result['errors'].append(f"Unsupported archive format: {archive_path}")
                return result
            
            # Create temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                extracted_files = self._extract_archive(archive_path, temp_dir)
                
                for file_info in extracted_files:
                    if result['files_processed'] >= self.max_files:
                        result['errors'].append(f"Reached maximum file limit ({self.max_files})")
                        break
                    
                    try:
                        text_content = self._extract_text_from_file(file_info)
                        if text_content:
                            result['text_content'][file_info['relative_path']] = text_content
                            result['total_text_length'] += len(text_content)
                            result['files_processed'] += 1
                            result['extracted_files'].append({
                                'path': file_info['relative_path'],
                                'size': file_info['size'],
                                'text_length': len(text_content)
                            })
                        else:
                            result['files_skipped'] += 1
                    except Exception as e:
                        result['errors'].append(f"Error processing {file_info['relative_path']}: {str(e)}")
                        result['files_skipped'] += 1
        
        except Exception as e:
            result['errors'].append(f"Error processing archive: {str(e)}")
            logger.error(f"Error processing archive {archive_path}: {e}")
        
        return result
    
    def _get_archive_type(self, file_path: str) -> str:
        """Get the archive type from file path."""
        file_path = file_path.lower()
        
        # Check compound extensions first
        for ext in ['.tar.gz', '.tar.bz2', '.tar.xz']:
            if file_path.endswith(ext):
                return self.SUPPORTED_ARCHIVES[ext]
        
        # Check single extensions
        for ext, archive_type in self.SUPPORTED_ARCHIVES.items():
            if file_path.endswith(ext):
                return archive_type
        
        return 'unknown'
    
    def _extract_archive(self, archive_path: str, extract_dir: str) -> List[Dict[str, Any]]:
        """
        Extract archive to directory and return file information.
        
        Args:
            archive_path: Path to archive file
            extract_dir: Directory to extract to
            
        Returns:
            List of file information dictionaries
        """
        archive_type = self._get_archive_type(archive_path)
        extracted_files = []
        
        try:
            if archive_type == 'zip':
                extracted_files = self._extract_zip(archive_path, extract_dir)
            elif archive_type == 'rar':
                extracted_files = self._extract_rar(archive_path, extract_dir)
            elif archive_type.startswith('tar'):
                extracted_files = self._extract_tar(archive_path, extract_dir, archive_type)
            elif archive_type in ['gzip', 'bzip2', 'xz']:
                extracted_files = self._extract_compressed(archive_path, extract_dir, archive_type)
            else:
                logger.warning(f"Unsupported archive type: {archive_type}")
        
        except Exception as e:
            logger.error(f"Error extracting {archive_type} archive {archive_path}: {e}")
            raise
        
        return extracted_files
    
    def _extract_zip(self, archive_path: str, extract_dir: str) -> List[Dict[str, Any]]:
        """Extract ZIP archive."""
        extracted_files = []
        
        with zipfile.ZipFile(archive_path, 'r') as zip_file:
            for file_info in zip_file.filelist:
                if file_info.is_dir():
                    continue
                
                if file_info.file_size > self.max_file_size:
                    logger.warning(f"Skipping large file: {file_info.filename} ({file_info.file_size} bytes)")
                    continue
                
                if self._is_text_file(file_info.filename):
                    try:
                        # Extract file
                        extracted_path = zip_file.extract(file_info, extract_dir)
                        
                        extracted_files.append({
                            'path': extracted_path,
                            'relative_path': file_info.filename,
                            'size': file_info.file_size
                        })
                    except Exception as e:
                        logger.warning(f"Error extracting {file_info.filename}: {e}")
        
        return extracted_files
    
    def _extract_rar(self, archive_path: str, extract_dir: str) -> List[Dict[str, Any]]:
        """Extract RAR archive."""
        extracted_files = []
        
        try:
            with rarfile.RarFile(archive_path, 'r') as rar_file:
                for file_info in rar_file.infolist():
                    if file_info.is_dir():
                        continue
                    
                    if file_info.file_size > self.max_file_size:
                        logger.warning(f"Skipping large file: {file_info.filename} ({file_info.file_size} bytes)")
                        continue
                    
                    if self._is_text_file(file_info.filename):
                        try:
                            # Extract file
                            extracted_path = rar_file.extract(file_info, extract_dir)
                            
                            extracted_files.append({
                                'path': extracted_path,
                                'relative_path': file_info.filename,
                                'size': file_info.file_size
                            })
                        except Exception as e:
                            logger.warning(f"Error extracting {file_info.filename}: {e}")
        
        except rarfile.RarCannotExec:
            logger.error("RAR extraction requires 'rar' or 'unrar' command line tools")
            raise Exception("RAR tools not available")
        
        return extracted_files
    
    def _extract_tar(self, archive_path: str, extract_dir: str, archive_type: str) -> List[Dict[str, Any]]:
        """Extract TAR archive (including compressed variants)."""
        extracted_files = []
        
        mode_map = {
            'tar': 'r',
            'tar.gz': 'r:gz',
            'tar.bz2': 'r:bz2',
            'tar.xz': 'r:xz'
        }
        
        mode = mode_map.get(archive_type, 'r')
        
        with tarfile.open(archive_path, mode) as tar_file:
            for member in tar_file.getmembers():
                if not member.isfile():
                    continue
                
                if member.size > self.max_file_size:
                    logger.warning(f"Skipping large file: {member.name} ({member.size} bytes)")
                    continue
                
                if self._is_text_file(member.name):
                    try:
                        # Extract file
                        tar_file.extract(member, extract_dir)
                        extracted_path = os.path.join(extract_dir, member.name)
                        
                        extracted_files.append({
                            'path': extracted_path,
                            'relative_path': member.name,
                            'size': member.size
                        })
                    except Exception as e:
                        logger.warning(f"Error extracting {member.name}: {e}")
        
        return extracted_files
    
    def _extract_compressed(self, archive_path: str, extract_dir: str, archive_type: str) -> List[Dict[str, Any]]:
        """Extract single compressed files (gzip, bzip2, xz)."""
        extracted_files = []
        
        # Determine the decompressed filename
        base_name = os.path.basename(archive_path)
        if archive_type == 'gzip' and base_name.endswith('.gz'):
            decompressed_name = base_name[:-3]
        elif archive_type == 'bzip2' and base_name.endswith('.bz2'):
            decompressed_name = base_name[:-4]
        elif archive_type == 'xz' and base_name.endswith('.xz'):
            decompressed_name = base_name[:-3]
        else:
            decompressed_name = base_name + '.decompressed'
        
        extracted_path = os.path.join(extract_dir, decompressed_name)
        
        try:
            # Open compressed file
            if archive_type == 'gzip':
                open_func = gzip.open
            elif archive_type == 'bzip2':
                open_func = bz2.open
            elif archive_type == 'xz':
                open_func = lzma.open
            else:
                raise ValueError(f"Unsupported compression type: {archive_type}")
            
            # Check if decompressed file would be a text file
            if self._is_text_file(decompressed_name):
                with open_func(archive_path, 'rb') as compressed_file:
                    with open(extracted_path, 'wb') as output_file:
                        # Decompress in chunks to handle large files
                        chunk_size = 8192
                        total_size = 0
                        
                        while total_size < self.max_file_size:
                            chunk = compressed_file.read(chunk_size)
                            if not chunk:
                                break
                            
                            output_file.write(chunk)
                            total_size += len(chunk)
                        
                        if total_size >= self.max_file_size:
                            logger.warning(f"Truncated large decompressed file: {decompressed_name}")
                
                extracted_files.append({
                    'path': extracted_path,
                    'relative_path': decompressed_name,
                    'size': os.path.getsize(extracted_path)
                })
        
        except Exception as e:
            logger.warning(f"Error decompressing {archive_path}: {e}")
        
        return extracted_files
    
    def _is_text_file(self, filename: str) -> bool:
        """Check if file is likely to contain text content."""
        file_ext = Path(filename).suffix.lower()
        
        # Check known text extensions
        if file_ext in self.TEXT_EXTENSIONS:
            return True
        
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type and mime_type.startswith('text/'):
            return True
        
        return False
    
    def _extract_text_from_file(self, file_info: Dict[str, Any]) -> Optional[str]:
        """
        Extract text content from a file.
        
        Args:
            file_info: File information dictionary
            
        Returns:
            Text content or None if not readable
        """
        file_path = file_info['path']
        
        try:
            # Try to read as text with different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    
                    # Basic validation - check if content seems like text
                    if self._is_likely_text(content):
                        return content
                
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    logger.warning(f"Error reading file {file_path} with encoding {encoding}: {e}")
                    continue
            
            # If all encodings failed, try binary mode and decode with errors='ignore'
            try:
                with open(file_path, 'rb') as f:
                    raw_content = f.read()
                    return raw_content.decode('utf-8', errors='ignore')
            except Exception as e:
                logger.warning(f"Failed to read file {file_path}: {e}")
        
        except Exception as e:
            logger.error(f"Error extracting text from {file_path}: {e}")
        
        return None
    
    def _is_likely_text(self, content: str) -> bool:
        """
        Check if content is likely to be text (vs binary).
        
        Args:
            content: Content to check
            
        Returns:
            True if likely text, False otherwise
        """
        if not content:
            return False
        
        # Check for high ratio of printable characters
        printable_chars = sum(1 for c in content if c.isprintable() or c.isspace())
        printable_ratio = printable_chars / len(content)
        
        # Consider it text if at least 80% of characters are printable
        return printable_ratio >= 0.8
    
    def get_archive_info(self, archive_path: str) -> Dict[str, Any]:
        """
        Get information about an archive without extracting it.
        
        Args:
            archive_path: Path to archive file
            
        Returns:
            Dictionary with archive information
        """
        info = {
            'path': archive_path,
            'type': self._get_archive_type(archive_path),
            'size': 0,
            'file_count': 0,
            'text_file_count': 0,
            'files': []
        }
        
        try:
            info['size'] = os.path.getsize(archive_path)
            archive_type = info['type']
            
            if archive_type == 'zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_file:
                    for file_info in zip_file.filelist:
                        if not file_info.is_dir():
                            info['file_count'] += 1
                            is_text = self._is_text_file(file_info.filename)
                            if is_text:
                                info['text_file_count'] += 1
                            
                            info['files'].append({
                                'name': file_info.filename,
                                'size': file_info.file_size,
                                'is_text': is_text
                            })
            
            elif archive_type == 'rar':
                try:
                    with rarfile.RarFile(archive_path, 'r') as rar_file:
                        for file_info in rar_file.infolist():
                            if not file_info.is_dir():
                                info['file_count'] += 1
                                is_text = self._is_text_file(file_info.filename)
                                if is_text:
                                    info['text_file_count'] += 1
                                
                                info['files'].append({
                                    'name': file_info.filename,
                                    'size': file_info.file_size,
                                    'is_text': is_text
                                })
                except rarfile.RarCannotExec:
                    info['error'] = "RAR tools not available"
            
            elif archive_type.startswith('tar'):
                mode_map = {
                    'tar': 'r',
                    'tar.gz': 'r:gz',
                    'tar.bz2': 'r:bz2',
                    'tar.xz': 'r:xz'
                }
                mode = mode_map.get(archive_type, 'r')
                
                with tarfile.open(archive_path, mode) as tar_file:
                    for member in tar_file.getmembers():
                        if member.isfile():
                            info['file_count'] += 1
                            is_text = self._is_text_file(member.name)
                            if is_text:
                                info['text_file_count'] += 1
                            
                            info['files'].append({
                                'name': member.name,
                                'size': member.size,
                                'is_text': is_text
                            })
            
            # Limit file list to prevent memory issues
            if len(info['files']) > 1000:
                info['files'] = info['files'][:1000]
                info['truncated'] = True
        
        except Exception as e:
            info['error'] = str(e)
            logger.error(f"Error getting archive info for {archive_path}: {e}")
        
        return info 