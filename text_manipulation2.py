# Import Deps
import re
import os

# Text Manipulation Functions
def regex_sha256(text):
    pattern = r"\b[A-Fa-f0-9]{64}\b"
    output =  re.findall(pattern, text)
    return set(output)

def grep_ipv4(text):
    pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    output = re.findall(pattern, text)
    return set(output)

def newline_to_space(text):
    return text.replace('\n', ' ').strip()

def remove_blank_lines(text):
    output_clean = "\n".join([line for line in text.split('\n') if line.strip()])
    return output_clean

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


# Menu Function
def menu_operations():
    global text
    while True:
        #os.system('clear')  # Clear terminal
        print("\nMenu:")
        print("1) Find Hashes")
        print("2) Find IPV4 Addresses")
        print("3) Newline Separated to Space Separated")
        print("4) Remove Blank Lines")
        print("5) Find URIs")
        print("6) Find URIs (DEFANGED)")
        print("7) Exit")
        print("9) Clear Teminal")
        print("10) Input new data")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            hash_submenu()

        elif choice == "2":
            output = grep_ipv4(text)
            print_output(output)

        elif choice == "3":
            output = newline_to_space(text)
            print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
            print(output)
            
        elif choice == "4":
            output = remove_blank_lines(text)
            print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
            print(output)

        elif choice == "5":
            clean = tuple_to_strings(text)
            for i in clean:
                print(i)

        elif choice == "6":
            clean = tuple_to_strings(text)
            for i in clean:
                print(i.replace('.', '[.]'))
        
        elif choice == "9":
            os.system('clear')

        elif choice == "10":
            get_input()

        elif choice == "7":
            break
        else:
            print("Invalid option, please try again.")



def hash_submenu():
    global text
    while True:
        #os.system('clear')  # Clear terminal
        print("\nHash Submenu:")
        print("1) Find SHA256")
        print("2) Back to Main Menu")
        print('\n' +'\n' + '\n')
        choice = input("Enter your choice: ")

        if choice == "1":
            output = regex_sha256(text)
            print_output(output)
        elif choice == "2":
            break
        else:
            print("Invalid option, please try again.")

def print_output(output):
    os.system('clear')  # Clear terminal
    print("OUTPUT BELOW" + '\n' + "------------" + '\n' + '\n')
    for i in output:
        print(i)

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