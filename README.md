# Python Socket Communication & Port Scanner Project

## 📌 Project Overview
This project demonstrates fundamental network programming and security automation skills using Python. It is divided into two components:

---

### 1️⃣ Client-Server Socket Communication
A TCP server listens for incoming messages while a client connects and exchanges data.  

**Features:**
- Proper connection setup and teardown
- Timestamps on all events for forensic evidence
- Error handling for downed server scenarios
- Clean shutdown process

---

### 2️⃣ TCP Port Scanner
A safe, ethical port scanner designed for **authorized scanning only**, including:
✅ Localhost (`127.0.0.1`)  
✅ `scanme.nmap.org`  

**Features:**
- Detection of open & closed ports
- Single port or range scanning
- Port number validation
- DNS / unreachable host error detection
- Adjustable scan delay (rate limiting / anti-DoS)
- Improved reliability with exception handling

---

## ✅ Repository Contents

| File | Description |
|------|-------------|
| `server.py` | TCP server that listens and receives data (timestamps included) |
| `client.py` | TCP client that connects and sends a timestamped message |
| `simple_scanner.py` | Ethical TCP port scanner with input validation & delay |
| `screenshots/` | Screenshot evidence of execution with timestamps |
| `CYB_333_Project_Fitzgerald.docx` | Final project report (uploaded after completion) |

---

## 🚀 How to Run

### ✅ Run the Server
```bash
python server.py
