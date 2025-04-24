import socket
import threading
import time
import sys
import os
import re
import logging
import traceback

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Logger configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecureChat-Client")

# Colors for output
COLORS = {
    'blue': '\033[94m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'red': '\033[91m',
    'purple': '\033[95m',
    'cyan': '\033[96m',
    'gray': '\033[90m',
    'bold': '\033[1m',
    'underline': '\033[4m',
    'end': '\033[0m'
}

# Globals
running = True
connected = False
reconnect_attempts = 0
MAX_RECONNECT_ATTEMPTS = 5
client_socket = None
aes_key = None

def print_banner():
    banner = f"""
{COLORS['cyan']}{COLORS['bold']}╔══════════════════════════════════════════╗
║             SECURE CHAT v1.0             ║
║        End-to-End Encryption             ║
╚══════════════════════════════════════════╝{COLORS['end']}
"""
    print(banner)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_loading(message, duration=3):
    chars = "|/-\\"
    for i in range(duration * 4):
        sys.stdout.write(f"\r{COLORS['cyan']}{message} {chars[i % 4]}{COLORS['end']}")
        sys.stdout.flush()
        time.sleep(0.25)
    sys.stdout.write("\r" + " " * (len(message) + 5) + "\r")

def timestamp():
    return f"{COLORS['gray']}[{time.strftime('%H:%M:%S')}]{COLORS['end']}"

def print_message(msg, msg_type="normal"):
    if msg_type == "system":
        print(f"{timestamp()} {COLORS['green']}{COLORS['bold']}[SYSTEM] {msg}{COLORS['end']}")
    elif msg_type == "error":
        print(f"{timestamp()} {COLORS['red']}{COLORS['bold']}[ERROR] {msg}{COLORS['end']}")
    elif msg_type == "debug":
        if logger.level <= logging.DEBUG:
            print(f"{timestamp()} {COLORS['gray']}{COLORS['bold']}[DEBUG] {msg}{COLORS['end']}")
    elif msg_type == "self":
        print(f"{timestamp()} {COLORS['purple']}{msg}{COLORS['end']}")
    else:
        print(f"{timestamp()} {msg}")

def format_chat_message(msg):
    if ': ' in msg:
        username, content = msg.split(': ', 1)
        content = re.sub(r'(:[a-zA-Z0-9_]+:)', f"{COLORS['yellow']}\\1{COLORS['end']}", content)
        content = re.sub(r'(https?://\S+)', f"{COLORS['cyan']}{COLORS['underline']}\\1{COLORS['end']}", content)
        return f"{COLORS['blue']}{username}:{COLORS['end']} {content}"
    return msg

def receive_messages(sock, local_key):
    global running, connected
    sock.settimeout(None)
    while running:
        try:
            data = sock.recv(4096)
            if not data:
                logger.warning("No data received; server closed connection.")
                break

            iv, ciphertext = data[:16], data[16:]
            cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            msg_bytes = unpadder.update(padded) + unpadder.finalize()

            # Safely decode UTF-8, replace invalid bytes
            try:
                msg = msg_bytes.decode('utf-8')
            except UnicodeDecodeError as ude:
                logger.error(f"Unicode decode error: {ude}. Replacing invalid bytes.")
                msg = msg_bytes.decode('utf-8', errors='replace')

            if "has joined the chat" in msg or "has left the chat" in msg:
                print_message(msg, "system")
            else:
                print_message(format_chat_message(msg))

        except (ConnectionResetError, ConnectionAbortedError):
            logger.error("Connection lost unexpectedly.")
            break
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            logger.debug(traceback.format_exc())
            break

    connected = False
    if running:
        print_message("Connection lost. Attempting to reconnect...", "error")
        try_reconnect()

def try_reconnect():
    global reconnect_attempts, client_socket, connected, running
    if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS:
        print_message(f"Could not reconnect after {MAX_RECONNECT_ATTEMPTS} attempts.", "error")
        running = False
        return
    reconnect_attempts += 1
    print_message(f"Reconnect attempt {reconnect_attempts}/{MAX_RECONNECT_ATTEMPTS}...", "system")
    time.sleep(2)
    try:
        connect_to_server(server_ip, username, is_reconnect=True)
    except Exception as e:
        logger.error(f"Reconnect failed: {e}")
        try_reconnect()

def send_encrypted_message(message, local_key, sock):
    try:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(message.encode('utf-8')) + padder.finalize()
        cipher = Cipher(algorithms.AES(local_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        sock.sendall(iv + ciphertext)
        return True
    except Exception as e:
        logger.error(f"Error sending message: {e}")
        return False

def connect_to_server(ip, user, is_reconnect=False):
    global client_socket, aes_key, connected
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    print_message(f"Connecting to {ip}:5555...", "debug")
    sock.connect((ip, 5555))

    # RSA handshake
    print_message("Waiting for server public key...", "debug")
    pub_pem = sock.recv(4096)
    if not pub_pem:
        raise Exception("No public key from server")
    pub_key = serialization.load_pem_public_key(pub_pem)
    print_message("Server public key received.", "debug")

    aes_key_local = os.urandom(32)
    encrypted_key = pub_key.encrypt(
        aes_key_local,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None)
    )
    print_message("Sending encrypted AES key...", "debug")
    sock.sendall(encrypted_key)

    print_message(f"Sending username: {user}", "debug")
    sock.sendall(user.encode('utf-8'))

    client_socket = sock
    aes_key = aes_key_local
    connected = True
    if not is_reconnect:
        show_loading("Securing connection", 2)
        print_message("Connected to server!", "system")
    else:
        print_message("Reconnected to server!", "system")

    threading.Thread(target=receive_messages, args=(sock, aes_key_local), daemon=True).start()
    return True

def show_help():
    help_text = f"""
{COLORS['cyan']}{COLORS['bold']}╔════════════════════════════════════════════════════════╗
║                 SECURE CHAT – HELP                    ║
╚════════════════════════════════════════════════════════╝{COLORS['end']}

{COLORS['bold']}Commands:{COLORS['end']}
{COLORS['yellow']}/help{COLORS['end']}   – Show this help
{COLORS['yellow']}/exit{COLORS['end']}   – Exit chat
{COLORS['yellow']}/clear{COLORS['end']}  – Clear screen
{COLORS['yellow']}/list{COLORS['end']}   – List users (admin only)
{COLORS['yellow']}/kick <user>{COLORS['end']} – Kick a user (admin only)
"""
    print(help_text)

def main():
    global server_ip, username, running, connected
    try:
        clear_screen()
        print_banner()
        server_ip = input(f"{COLORS['cyan']}Server IP {COLORS['bold']}> {COLORS['end']}")
        username  = input(f"{COLORS['cyan']}Your name {COLORS['bold']}> {COLORS['end']}")

        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', server_ip):
            print_message("Invalid IP address.", "error")
            return
        if not (3 <= len(username) <= 20):
            print_message("Username must be 3–20 characters.", "error")
            return

        clear_screen()
        print_banner()
        connect_to_server(server_ip, username)

        show_help()
        prompt = f"{COLORS['purple']}{username}{COLORS['end']} > "

        while running:
            try:
                msg = input(prompt)
                if msg.startswith('/'):
                    cmd = msg.lower().split()[0]
                    if cmd in ['/exit', '/help', '/clear']:
                        if cmd == '/exit':
                            print_message("Exiting chat...", "system")
                            running = False
                            break
                        elif cmd == '/clear':
                            clear_screen()
                            print_banner()
                            continue
                        elif cmd == '/help':
                            show_help()
                            continue
                    print_message(f"{username}: {msg}", "self")
                    if not send_encrypted_message(msg, aes_key, client_socket):
                        print_message("Failed to send command.", "error")
                        connected = False
                        try_reconnect()
                    continue

                if not connected:
                    print_message("Not connected to server.", "error")
                    continue

                if msg.strip():
                    print_message(f"{username}: {msg}", "self")
                    if not send_encrypted_message(msg, aes_key, client_socket):
                        print_message("Message send failed.", "error")
                        connected = False
                        try_reconnect()
            except KeyboardInterrupt:
                print("\n")
                print_message("Exiting chat...", "system")
                running = False
                break
            except Exception as e:
                logger.error(f"Main loop error: {e}")
                logger.debug(traceback.format_exc())
    except KeyboardInterrupt:
        print("\n")
        print_message("Program aborted.", "system")
    finally:
        running = False
        if client_socket:
            try: client_socket.close()
            except: pass
        print_message("Program terminated.", "system")

if __name__ == "__main__":
    main()
