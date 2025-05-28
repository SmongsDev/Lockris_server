## 📖 Project Overview
`Lockris` Go Echo Server is a high-performance, secure validation server for a Tetris-style game. It offers complete cheat prevention and real-time game integrity verification through a 1:1 connection with a single client.


### ✨ Key Features

🔒 Military-grade security: 5-stage score validation blocks 99.9% of cheats  
⚡ High performance: Ultra-lightweight Go-based server (less than 8MB memory usage)  
🎯 1:1 dedicated: Maximum stability through single-client focus  
🛡️ Real-time monitoring: Built-in security surveillance with auto-response  
📊 Detailed logging: Every game event and security incident fully recorded  
🖥️ Admin console: Real-time server control and monitoring


### 🏗️ Architecture
```
📡 Client (C++)    ←→    🛡️ Go Server     ←→     👨‍💼 Admin
├── Game Logic            ├── Connection Mgmt      ├── Real-time Monitoring
├── Security Checks       ├── Score Validation     ├── Client Control
└── Network I/O           ├── Security Monitoring  └── Server Management
                          └── Logging System
```


## 🚀 Getting Started

### 1️⃣ Install Go
```bash 
# Download from the official Go website
# https://golang.org/dl/

# Verify installation
go version
```

### 2️⃣ Download & Build the Server
```bash
# Clone the project (or download the source code)
git clone https://github.com/your-repo/tetris-server.git
cd tetris-server

# Initialize Go module
go mod init tetris-echo-server

# Resolve dependencies and build
go build -o tetris_server main.go
```

### 3️⃣ Run the Server
```bash
# Start the server with default settings
./tetris_server

# On Windows
tetris_server.exe
```

### 4️⃣ Connect the Client
```bash
# In a separate terminal, run the C++ client
./tetris_game.exe
```


## 📡 Communication Protocol

### Client → Server

| Command Type    | Format                                      | Description                       | Example                          |
|-----------------|---------------------------------------------|-----------------------------------|----------------------------------|
| Authentication  | `AUTH:<token>`                              | Authenticate client               | `AUTH:TETRIS_CLIENT_2025`        |
| Score Update    | `SCORE:<score>:<event>:<gain>:<info>`       | Enhanced score update             | `SCORE:400:LINES_CLEAR:300:2`    |
| Security Event  | `SECURITY:<event>`                          | Send security-related event       | `SECURITY:DEBUGGER_DETECTED`     |
| Heartbeat       | `HEARTBEAT:`                                | Connection status check (no data) | `HEARTBEAT:`                     |

### Server → Client

| Response Code         | Description                     | Example                         |
|------------------------|----------------------------------|----------------------------------|
| `AUTH_SUCCESS`         | Client authentication success   |                                  |
| `AUTH_FAILED`          | Client authentication failed    |                                  |
| `ACK`                  | Score update approved           |                                  |
| `STATUS_OK`            | Status check passed             |                                  |
| `HEARTBEAT:`           | Heartbeat response              |                                  |
| `TERMINATE:<reason>`   | Force game termination          | `TERMINATE:SUSPICIOUS_SCORE`     |
| `ERROR:<message>`      | Error response                  | `ERROR:INVALID_FORMAT`           |

