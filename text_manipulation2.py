# Import Deps
import re
import os
import pyperclip

# Globals
previous_output = ""

# Text Manipulation Functions

# Hashes
def regex_sha256(text):
    pattern = r"\b[A-Fa-f0-9]{64}\b"
    output =  re.findall(pattern, text)
    return set(output)

def regex_sha1(text):
    pattern = r"\b[a-fA-F0-9]{40}\b"
    output = re.findall(pattern, text)
    return set(output)

def regex_md5(text):
    pattern = r"([a-fA-F\d]{32})"
    output = re.findall(pattern, text)
    return set(output)
# IP Addresses
def grep_ipv4(text):
    pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    output = re.findall(pattern, text)
    return set(output)
# Text Manipulation
def newline_to_space(text):
    return text.replace('\n', ' ').strip()

def remove_blank_lines(text):
    output_clean = "\n".join([line for line in text.split('\n') if line.strip()])
    return output_clean
# URI(s)
def return_urls(text):
    pattern = r"(((https://)|(http://))?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"
    return re.findall(pattern, text)

def defang_urls(text):
    return_urls(text)

def tuple_to_strings(text):
    output = return_urls(text)
    print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
    clean = []
    for url_tuple in output:
        for url in url_tuple:
            if url and '.' in url:  # Check if it's a URL
                if url.startswith(('http://', 'https://')) and not url.startswith('/'):
                    clean.append(url)
            elif url and not url.startswith(('http://', 'https://')) and not url.startswith('/'):
                clean.append(url)
    return set(clean)

# Files
def executable_finder(text):
    print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
    pattern = r"([^,\s]+\.exe|[^,\s]+\.bat|[^,\s]+\.cmd|[^,\s]+\.sh|[^,\s]+\.bin)\b"
    output = re.findall(pattern, text)
    return set(output)


# Menu Function
def menu_operations():
    global text, previous_output
    while True:
        #os.system('clear')  # Clear terminal
        print("\nMenu:")
        print("1) Find Hashes")
        print("2) Find IPV4 Addresses")
        print("3) Newline Separated to Space Separated")
        print("4) Remove Blank Lines")
        print("5) Find URIs")
        print("7) File Finder")
        print("8) Exit")
        print("9) Clear Terminal")
        print("10) Input new data")
        print("11) Store Previous Output to Clipboard")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            os.system('clear')  # Clear terminal
            hash_submenu()

        elif choice == "2":
            output = grep_ipv4(text)
            previous_output = output
            print_output(output)

        elif choice == "3":
            output = newline_to_space(text)
            previous_output = output
            print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
            print(output)
            
        elif choice == "4":
            output = remove_blank_lines(text)
            previous_output = output
            print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
            print(output)

        elif choice == "5":
            os.system('clear')  # Clear terminal
            URI_submenu()

        elif choice == "7":
            os.system('clear')  # Clear terminal
            file_finder_submenu()
        
        elif choice == "9":
            os.system('clear')

        elif choice == "10":
            get_input()

        elif choice == "11":
            copy_output(previous_output)

        elif choice == "8":
            os.system('clear')  # Clear terminal
            break
        else:
            print("Invalid option, please try again.")

# Submenus

def URI_submenu():
    global text, previous_output
    output = []
    while True:
        print("\nURI Submenu:")
        print("1) Find URI")
        print("2) Find URI [DEFANGED]")
        print("3) Clear Terminal")
        print("4) Copy Previous Output to Clipboard")
        print("5) Return to Main Menu")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            output = ""
            output2 = tuple_to_strings(text)
            for i in output2:
                print(i)
                output += '\n' + i
        elif choice == "2":
            output = ""
            output2 = tuple_to_strings(text)
            for i in output2:
                print(i.replace('.', '[.]'))
                i = i.replace('.', '[.]')
                output += '\n' + i
        elif choice == "3":
            os.system("clear")
        elif choice == "4":
            copy_output(output)
        elif choice == "5":
            break

def hash_submenu():
    global text, previous_output
    while True:
        #os.system('clear')  # Clear terminal
        print("\nHash Submenu:")
        print("1) Find SHA256")
        print("2) Find SHA1")
        print("3) Find MD5")
        print("4) Store Previous Output to Clipboard")
        print("5) Back to Main Menu")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            output = regex_sha256(text)
            print_output(output)
        elif choice == "2":
            output = regex_sha1(text)
            print_output(output)
        elif choice == "3":
            output = regex_md5(text)
            print_output(output)
        elif choice == "4":
            copy_output(previous_output)
        elif choice == "5":
            os.system('clear')  # Clear terminal
            break
        else:
            print("Invalid option, please try again.")

def file_finder_submenu():
    global text, previous_output
    while True:
        print('\n File Finder Submenu:')
        print("1) Find Executables")
        print("2) Return to Main Menu")
        print("3) Store Previous Output to Clipboard")
        print("9) Clear Terminal")
        choice = input("Enter your choice: ")

        if choice == "1":
            output = ""
            output2 = executable_finder(text)
            for exe in output2:
                output += '\n' + exe
            print_output(output2)
        elif choice == "3":
            copy_output(output)
        elif choice == "9":
            os.system("clear")
        elif choice == "2":
            os.system('clear')  # Clear terminal
            break
# Output operations        

def print_output(output):
    global previous_output
    os.system('clear')  # Clear terminal
    print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
    for i in output:
        print(i)
    previous_output = '\n'.join(output) # Store the output

def copy_output(output):
    if output:
        pyperclip.copy(output)
        print("Output copied to clipboard.")
    else:
        print("No output to copy.")

def get_input():
    global text
    while True:
        choice = input("\nEnter 'I' for input or 'F' for file path: ")
        if choice.upper() == 'I':
            print("Enter your text (type DONE! or press Ctrl + D (Linux) or Ctrl + Z (Windows) to finish):")
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    break

                if line.strip().upper() == "DONE!":
                    break
                lines.append(line)
            
            text = '\n'.join(lines)
            break
        elif choice.upper() == 'F':
            file_path = input("Enter the file path: ")
            try:
                with open(file_path, 'r') as file:
                    text = file.read()
                break
            except FileNotFoundError:
                print("File not found. Please enter a valid file path.")
        else:
            print("Invalid option, please try again.")

# Main Loop
if __name__ == "__main__":
    text = ''
    get_input()
    menu_operations()
