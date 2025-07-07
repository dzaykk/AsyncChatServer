# AsyncChatServer

AsyncChatServer is an asynchronous chat server implemented in C++ using the Boost.ASIO library for network communication and OpenSSL for secure TLS-based connections. The server supports user registration, authentication, peer-to-peer chat sessions, and message exchange, with a robust SQLite-based backend for user data persistence. Designed for scalability and security, it leverages modern C++20 standards and asynchronous I/O to handle multiple client connections efficiently.

# Features

-	Asynchronous Communication: Built with Boost.ASIO for non-blocking, high-performance network operations.
-	Secure Connections: Utilizes OpenSSL for TLS encryption, ensuring secure communication with certificate-based authentication.
-	User Management: Supports user registration and authentication with secure password hashing (SHA-256 with salt) stored in an SQLite database.
-	Peer-to-Peer Chat: Enables users to find and connect with other online users for private chat sessions.
-	Robust Protocol: Implements a custom binary protocol with CRC32 checksums for reliable data transmission.
-	Logging: Includes a thread-safe logging system for debugging and monitoring server activity.
-	Cross-Platform: Compatible with Windows, Linux, and macOS (with platform-specific linking for Windows and Linux).

# Prerequisites

To build and run AsyncChatServer, ensure the following dependencies are installed:

-	CMake: Version 3.25 or higher.
-	C++ Compiler: Supporting C++20 (e.g., GCC, Clang, MSVC).
-	Boost: Version 1.88.0 or higher (with system component).
-	OpenSSL: Version 3.0.0 or higher.
-	SQLite: Included as a static library in thirdparty/sqlite.

# Platform-Specific Requirements

-	Windows: Requires crypt32 and ws2_32 libraries.
-	Linux: Requires pthread and dl libraries.

# Building the Project

1.	Clone the Repository:
git clone https://github.com/dzaykk/AsyncChatServer.git
cd AsyncChatServer

2.	Create a Build Directory:
mkdir build
cd build

3.	Run CMake:
cmake ..

4.	Build the Project:
cmake --build . --config Release

5.	Generate SSL Certificates (if not provided):
Generate server.crt, server.key, and dh.pem using OpenSSL

-	openssl genrsa -out certs/server.key 2048
-	openssl req -new -x509 -days 365 -key certs/server.key -out certs/server.crt
-	openssl dhparam -out certs/dh.pem 2048


# Running the Server

1.	Ensure the SQLite database file (users.db) is located at thirdparty/sqlite/users.db. The server will create the database and necessary tables automatically if they do not exist.
2.	Run the server executable:
./AsyncChatServer

3.	The server listens on port 5555 by default. Logs are written to logs/server.log.

# Usage

1.	Client Connection:
	-	Clients connect to the server using a TLS-enabled client application (not included in this repository).
	-	The server expects a custom binary protocol (defined in protocol.hpp) for communication.
2.	Supported Commands:
	-	Register: Register a new user with a username and password.
	-	Login: Authenticate an existing user.
	-	FindPeer: Search for another online user to initiate a chat.
	-	Message: Send a chat message to the connected peer.
	-	Ack/Error: Handle protocol responses and errors.
	-	ExitChat: Terminate the current chat session.
3.	Protocol Details:
	-	Packets include a magic header (MAGC), command type, body length, payload, and CRC32 checksum.
	-	Messages are serialized/deserialized using the proto::serialize and proto::deserialize functions.

# Example Workflow

1.	A client connects and sends a Register or Login packet with username:password.
2.	Upon successful authentication, the client can send a FindPeer packet with the target user’s username.
3.	If the peer is online, the server facilitates a chat session, relaying Message packets between users.
4.	Either user can send /exit to terminate the chat session.

# Logging

The server logs all significant events (e.g., client connections, errors, and protocol issues) to logs/server.log. Logs include timestamps and log levels (INFO, WARNING, ERR).

Example log entry:

[2025-07-07 14:22:33] [INFO] Client connected
[2025-07-07 14:22:35] [ERR] Handshake failed: Connection reset by peer

# Contributing

Contributions are welcome! Please follow these steps:

1.	Fork the repository.
2.	Create a feature branch (git checkout -b feature/your-feature).
3.	Commit your changes (git commit -m "Add your feature").
4.	Push to the branch (git push origin feature/your-feature).
5.	Open a pull request.

# License

This project is licensed under the MIT License. See the LICENSE file for details.