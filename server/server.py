import socket
import threading
import time
import os
import signal
import sys
import logging
import traceback
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logger
tlogging = logging.getLogger("SecureChat-Server")
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server_log.txt"),
        logging.StreamHandler()
    ]
)

# Server configuration
HOST = '0.0.0.0'
PORT = 5555
admin_password = "admin123"  # CHANGE in production
keep_alive_interval = 30       # Seconds

# Generate RSA key pair
logging.info("Generating RSA keys...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
logging.info("RSA keys generated")

# Global state
clients = []
clients_lock = threading.Lock()
connection_count = 0
server_running = True
shutdown_flag = threading.Event()

# ANSI colors pool
COLOR_CODES = ['\033[91m','\033[92m','\033[93m','\033[94m','\033[95m','\033[96m']
COLOR_RESET = '\033[0m'
next_color = 0

def print_server_banner():
    banner = f"""
{COLOR_CODES[3]}╔══════════════════════════════════════════╗
║        SECURE CHAT SERVER v1.1           ║
║    Running on {HOST}:{PORT}             ║
╚══════════════════════════════════════════╝{COLOR_RESET}
"""
    print(banner)
    print("Admin commands:")
    print("/admin <password>         -- become admin")
    print("/list                     -- list users")
    print("/kick <user> [reason]     -- kick user")
    print("/ban <user> [reason]      -- ban user by IP")
    print("/msg <user> <message>     -- private message")
    print("/broadcast <message>      -- send announcement")
    print("/stats                    -- server statistics")
    print("/shutdown                 -- shutdown server")

def assign_color():
    global next_color
    code = COLOR_CODES[next_color % len(COLOR_CODES)]
    next_color += 1
    return code

def send_encrypted_message(sock, aes_key, message):
    try:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(message.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        sock.sendall(iv + ciphertext)
        return True
    except Exception as e:
        logging.error(f"Error sending to {sock.getpeername()}: {e}")
        return False

def broadcast(message, sender=None, admin_only=False):
    logging.debug(f"Broadcast: {message} (admin_only={admin_only})")
    with clients_lock:
        for c in list(clients):
            try:
                if sender and c['socket'] == sender:
                    continue
                if admin_only and not c['is_admin']:
                    continue
                # prefix user-specific color
                prefix = c['color']
                send_encrypted_message(c['socket'], c['aes_key'], prefix + message + COLOR_RESET)
            except Exception as e:
                logging.error(f"Broadcast error to {c['username']}: {e}")
                clients.remove(c)

def handle_client_command(sock, aes_key, text, username):
    parts = text.split()
    cmd = parts[0].lower()
    with clients_lock:
        client = next((c for c in clients if c['socket'] == sock), None)
    if not client:
        return
    is_admin = client['is_admin']

    if cmd == '/admin':
        if len(parts) < 2:
            send_encrypted_message(sock, aes_key, "Usage: /admin <password>")
            return
        if parts[1] == admin_password:
            client['is_admin'] = True
            send_encrypted_message(sock, aes_key, "You are now admin.")
            logging.info(f"{username} granted admin")
        else:
            send_encrypted_message(sock, aes_key, "Incorrect password.")
        return

    if cmd == '/help':
        help_text = (
            "Available:\n"
            "/help /admin /whisper /me\n"
            "Admin only: /list /kick /ban /broadcast /stats /shutdown"
        )
        send_encrypted_message(sock, aes_key, help_text)
        return

    if cmd in ['/whisper', '/w', '/msg']:
        if len(parts) < 3:
            send_encrypted_message(sock, aes_key, "Usage: /msg <user> <message>")
            return
        target = parts[1]
        msg = ' '.join(parts[2:])
        with clients_lock:
            dest = next((c for c in clients if c['username'].lower() == target.lower()), None)
        if not dest:
            send_encrypted_message(sock, aes_key, f"User {target} not found.")
        else:
            send_encrypted_message(dest['socket'], dest['aes_key'], f"[PM from {username}] {msg}")
            send_encrypted_message(sock, aes_key, f"[PM to {dest['username']}] {msg}")
        return

    if cmd == '/me':
        if len(parts) < 2:
            send_encrypted_message(sock, aes_key, "Usage: /me <action>")
            return
        act = ' '.join(parts[1:])
        broadcast(f"* {username} {act}")
        return

    if not is_admin:
        send_encrypted_message(sock, aes_key, "Permission denied.")
        return

    if cmd == '/list':
        with clients_lock:
            lines = [f"{c['username']} (ID {c['id']}) - {int((time.time()-c['connected_at'])/60)}m" for c in clients]
        send_encrypted_message(sock, aes_key, "Users:\n" + "\n".join(lines))
        return

    if cmd == '/kick':
        if len(parts) < 2:
            send_encrypted_message(sock, aes_key, "Usage: /kick <user> [reason]")
            return
        target = parts[1]
        reason = ' '.join(parts[2:]) or 'no reason'
        with clients_lock:
            tgt = next((c for c in clients if c['username'].lower() == target.lower()), None)
        if not tgt or tgt['is_admin']:
            send_encrypted_message(sock, aes_key, "Cannot kick.")
        else:
            send_encrypted_message(tgt['socket'], tgt['aes_key'], f"You were kicked by {username}: {reason}")
            broadcast(f"{tgt['username']} kicked ({reason})")
            tgt['socket'].close()
            clients.remove(tgt)
            send_encrypted_message(sock, aes_key, f"{target} kicked.")
        return

    if cmd == '/ban':
        if len(parts) < 2:
            send_encrypted_message(sock, aes_key, "Usage: /ban <user> [reason]")
            return
        target = parts[1]
        reason = ' '.join(parts[2:]) or 'no reason'
        with clients_lock:
            tgt = next((c for c in clients if c['username'].lower() == target.lower()), None)
        if not tgt or tgt['is_admin']:
            send_encrypted_message(sock, aes_key, "Cannot ban.")
        else:
            tgt['banned'] = True
            ip = tgt['address'][0]
            send_encrypted_message(tgt['socket'], tgt['aes_key'], f"You are banned by {username}: {reason}")
            broadcast(f"{tgt['username']} banned ({reason})")
            tgt['socket'].close()
            clients.remove(tgt)
            send_encrypted_message(sock, aes_key, f"{target} banned.")
        return

    if cmd in ['/broadcast', '/bc']:
        if len(parts) < 2:
            send_encrypted_message(sock, aes_key, "Usage: /broadcast <message>")
            return
        msg = ' '.join(parts[1:])
        broadcast(f"[ANNOUNCE] {msg}")
        return

    if cmd == '/stats':
        up = int(time.time() - start_time)
        m, s = divmod(up, 60)
        h, m = divmod(m, 60)
        with clients_lock:
            cu = len(clients)
        stats = f"Uptime: {h}h{m}m{s}s, Users: {cu}, Total conn: {connection_count}\n"
        send_encrypted_message(sock, aes_key, stats)
        return

    if cmd == '/shutdown':
        send_encrypted_message(sock, aes_key, "Shutting down...")
        logging.warning(f"Shutdown by {username}")
        broadcast("Server shutting down in 5s...")
        threading.Thread(target=lambda: (time.sleep(5), shutdown()), daemon=True).start()
        return

    send_encrypted_message(sock, aes_key, f"Unknown command: {cmd}")

def keep_alive(sock, aes_key):
    while server_running and not shutdown_flag.is_set():
        try:
            with clients_lock:
                if not any(c['socket'] == sock for c in clients):
                    break
            send_encrypted_message(sock, aes_key, '__ping__')
            time.sleep(keep_alive_interval)
        except:
            break

def handle_client(sock, addr):
    global connection_count
    connection_count += 1
    cid = connection_count
    aes_key = None
    username = None
    try:
        sock.sendall(public_pem)
        encrypted_key = sock.recv(1024)
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        username = sock.recv(1024).decode()
        if not username:
            raise ValueError('no name')
        with clients_lock:
            if any(c['username'].lower() == username.lower() for c in clients):
                send_encrypted_message(sock, aes_key, 'ERROR: Username taken')
                return
        color = assign_color()
        info = {
            'socket': sock,
            'aes_key': aes_key,
            'username': username,
            'address': addr,
            'id': cid,
            'connected_at': time.time(),
            'is_admin': False,
            'banned': False,
            'color': color
        }
        with clients_lock:
            clients.append(info)
        threading.Thread(target=keep_alive, args=(sock, aes_key), daemon=True).start()
        send_encrypted_message(sock, aes_key, 'Connection established!')
        broadcast(f"{username} joined")
        while server_running and not shutdown_flag.is_set():
            data = sock.recv(1024)
            if not data:
                break
            iv, ct = data[:16], data[16:]
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            dec = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            txt = unpadder.update(dec) + unpadder.finalize()
            msg = txt.decode()
            if msg in ('__ping__', '__pong__'):
                send_encrypted_message(sock, aes_key, '__pong__')
                continue
            if msg.startswith('/'):
                handle_client_command(sock, aes_key, msg, username)
            else:
                broadcast(f"{username}: {msg}", sender=sock)
    except Exception as e:
        logging.error(f"Error {username or cid}: {e}")
        traceback.print_exc()
    finally:
        with clients_lock:
            clients[:] = [c for c in clients if c['socket'] != sock]
        sock.close()
        if username:
            broadcast(f"{username} left")

def shutdown():
    global server_running
    server_running = False
    shutdown_flag.set()
    broadcast("Server is shutting down now")

def main():
    global start_time
    start_time = time.time()
    signal.signal(signal.SIGINT, lambda s,f: shutdown())
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print_server_banner()
    logging.info(f"Server listening on {HOST}:{PORT}")
    while server_running:
        try:
            server.settimeout(1.0)
            sock, addr = server.accept()
            with clients_lock:
                if any(c['banned'] and c['address'][0] == addr[0] for c in clients):
                    sock.close()
                    continue
            threading.Thread(target=handle_client, args=(sock, addr), daemon=True).start()
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Accept error: {e}")
    server.close()
    logging.info("Shutdown complete.")

if __name__ == '__main__':
    main()