# Secure Chat - End-to-End Encrypted Client-Server Chat Application

## Overview

Secure Chat is a Python-based client-server chat application that provides end-to-end encrypted communication between users. It uses RSA asymmetric encryption for secure key exchange and AES symmetric encryption for message confidentiality. The system supports multiple clients connecting to a central server, with features such as user commands, admin controls, and robust connection handling.

## Features

- End-to-end encryption using RSA and AES
- Secure key exchange with RSA public/private keys
- AES encryption for all chat messages
- User-friendly command interface with commands like `/help`, `/exit`, `/clear`
- Admin commands for managing users: `/admin`, `/list`, `/kick`, `/ban`, `/broadcast`, `/stats`, `/shutdown`
- Automatic reconnection attempts on connection loss (client-side)
- Color-coded user messages and system notifications
- Logging of client and server events to separate log files
- Keep-alive pings to maintain active connections
- Support for private messaging and user actions

## Requirements

- Python 3.6 or higher
- [cryptography](https://cryptography.io/en/latest/) library

Install dependencies with:

```bash
pip install cryptography
```

## Installation

1. Clone or download this repository.
2. Ensure Python 3 and the `cryptography` package are installed.
3. Navigate to the project directory.

## Usage

### Running the Server

1. Open a terminal.
2. Navigate to the `server` directory or the project root.
3. Run the server script:

```bash
python server/server.py
```

The server listens on all interfaces (`0.0.0.0`) at port `5555` by default.

### Running the Client

1. Open a terminal.
2. Navigate to the `client` directory or the project root.
3. Run the client script:

```bash
python client/client.py
```

4. When prompted, enter the server IP address and your username.
5. Use the chat interface to send messages.

## Commands

### Client Commands

- `/help` - Show help information
- `/exit` - Exit the chat client
- `/clear` - Clear the chat screen
- `/list` - List users (admin only)
- `/kick <user>` - Kick a user (admin only)

### Server Admin Commands

- `/admin <password>` - Become admin (default password: `admin123`, change in production)
- `/list` - List connected users
- `/kick <user> [reason]` - Kick a user
- `/ban <user> [reason]` - Ban a user by IP
- `/msg <user> <message>` - Send a private message
- `/broadcast <message>` - Send an announcement to all users
- `/stats` - Show server statistics
- `/shutdown` - Shutdown the server

## Security

- The server generates an RSA key pair on startup.
- Clients receive the server's public key and use it to encrypt a randomly generated AES key.
- All subsequent messages are encrypted with AES in CBC mode using the shared AES key.
- Messages are padded using PKCS7 padding.
- The system uses a secure key exchange and symmetric encryption to ensure confidentiality.
- Usernames must be unique and between 3 and 20 characters.
- Admin password should be changed from the default for production use.

## Logging

- Client logs are saved to `client_log.txt`.
- Server logs are saved to `server_log.txt`.
- Logs include debug, info, warning, and error messages.

## Notes

- The client attempts to reconnect automatically up to 5 times if the connection is lost.
- The server supports multiple concurrent clients using threading.
- The server broadcasts user join/leave notifications.
- The client supports emoji codes and clickable URLs in messages.

## License

MIT

---

Developed as a secure, simple chat application demonstrating end-to-end encryption principles in Python.
