# XPing

🚀 **Multi-Protocol Connection Ping Tool using Xray with fragment support**

A powerful command-line tool for testing proxy connections (VLESS, VMESS, Shadowsocks, Trojan) with advanced features like fragment support, real-time ping statistics, and automatic port management.

---

## 🎬 Demo Video

https://github.com/user-attachments/assets/6dd3f671-5469-441a-91c0-00b1028e2708

---

## ✨ Features

- 🔗 **Multi-Protocol Support**: Test VLESS, VMESS, Shadowsocks (SS), and Trojan protocols
- 📁 **Config File Support**: Use existing Xray config files for testing
- 🧩 **Fragment Mode**: Enable fragment for bypassing censorship
- 📊 **Real-time Statistics**: Live ping results with detailed min/max/avg stats
- 🎯 **Smart Port Management**: Automatic free port detection to avoid conflicts
- 🌈 **Colorful Output**: Beautiful colored terminal output with emojis
- ⚙️ **Environment Variables**: Customizable via environment variables
- 🛡️ **Config Validation**: Built-in Xray config validation
- 🔍 **Protocol Detection**: Automatic protocol detection from URL scheme

---

## 📦 Installation

### Prerequisites

- **Node.js** 16.0.0 or higher
- **Xray-core** installed and accessible

### Install via npm (Global)

```bash
npm install -g @nabikaz/xping
```

### Manual Installation

```bash
git clone https://github.com/NabiKAZ/xping.git
cd xping
npm install
```

---

## 🚀 Usage

### Basic Usage

```bash
# Test with VLESS URL
xping "vless://uuid@server:port?security=tls&type=ws&path=/..."

# Test with VMESS URL (base64 encoded)
xping "vmess://base64-encoded-config"

# Test with Shadowsocks URL
xping "ss://method:password@server:port"

# Test with Trojan URL
xping "trojan://password@server:port?security=tls"

# Test with config file
xping config.json

# Test with fragment mode
xping "vless://..." --fragment

# Test with custom options
xping config.json --count 10 --delay 2000 --timeout 5000
```

### Command Line Options

```
Usage: xping <input> [options]

Arguments:
  input  Protocol URL (vless://, vmess://, ss://, trojan://) or xray config file

Options:
  -f, --fragment  Enable fragment mode (default: false)
  -d, --delay     Delay between pings in milliseconds (default: 1000)
  -t, --timeout   Connection timeout in milliseconds (default: 10000)
  -c, --count     Number of pings to send (default: infinite)
  -h, --help      Show help
  -v, --version   Show version number
```

### Supported Protocols

| Protocol | URL Format | Example |
|----------|-----------|----------|
| **VLESS** | `vless://uuid@host:port?...` | `vless://abc123@example.com:443?security=tls&type=ws` |
| **VMESS** | `vmess://base64-config` | `vmess://ew0KICAidiI6ICIyIiwNCiAgImlkIjog...` |
| **Shadowsocks** | `ss://method:password@host:port` | `ss://aes-256-gcm:pass@example.com:8388` |
| **Trojan** | `trojan://password@host:port?...` | `trojan://pwd@example.com:443?security=tls` |

### Examples

```bash
# VLESS protocol test
xping "vless://abc123@example.com:443?security=tls&type=ws&path=/"

# VMESS protocol test
xping "vmess://ew0KICAidiI6ICIyIiwDQiAgImlkIjogImFiYzEyMyIsDQogIC4uLn0="

# Shadowsocks protocol test
xping "ss://aes-256-gcm:mypassword@example.com:8388"

# Trojan protocol test
xping "trojan://mypassword@example.com:443?security=tls&sni=example.com"

# Test with fragment enabled (URL protocols only)
xping "vless://abc123@example.com:443?..." --fragment

# Test config file with limited count
xping config.json --count 5

# Test with custom timing
xping config.json --delay 500 --timeout 15000 --count 10

# Continuous testing (Ctrl+C to stop)
xping "vless://..."
```

---

## 🔧 Environment Variables

Configure XPing behavior using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `XPING_XRAY_PATH` | Path to xray binary | `xray` |
| `XPING_TARGET_URL` | Target URL for testing | `https://www.google.com/generate_204` |
| `XPING_FRAGMENT_PACKETS` | Fragment packets type | `tlshello` |
| `XPING_FRAGMENT_LENGTH` | Fragment length range | `5-9` |
| `XPING_FRAGMENT_INTERVAL` | Fragment interval range | `1-2` |

### Example with Environment Variables

```bash
# Linux/macOS
export XPING_XRAY_PATH="/usr/local/bin/xray"
export XPING_TARGET_URL="https://www.cloudflare.com"
xping config.json

# Windows Command Prompt
set XPING_XRAY_PATH="C:\xray\xray.exe"
set XPING_TARGET_URL="https://www.cloudflare.com"
xping config.json

# Windows PowerShell
$env:XPING_XRAY_PATH="C:\xray\xray.exe"
$env:XPING_TARGET_URL="https://www.cloudflare.com"
xping config.json
```

---

## 🛠️ How It Works

1. **Input Detection**: Automatically detects whether input is a VLESS URL or config file
2. **Config Processing**: 
   - For VLESS URLs: Generates optimized Xray config
   - For config files: Processes in memory with free port assignment
3. **Validation**: Validates configuration using `xray -test`
4. **Proxy Setup**: Starts Xray with automatic port management
5. **Connection Testing**: Performs HTTP requests through the proxy
6. **Statistics**: Provides real-time and summary statistics

---

## 💸 Donate

If you find this tool useful and would like to support its development:

- TON Wallet: `nabikaz.ton`

---

## 📄 License

This project is licensed under the **GNU GPLv3** - see the [LICENSE](LICENSE) file for details.

---

⭐ **Star this project if you find it useful!**
