# XPing

🚀 **VLESS connection ping tool using Xray with fragment support**

A powerful command-line tool for testing VLESS proxy connections with advanced features like fragment support, real-time ping statistics, and automatic port management.

## ✨ Features

- 🔗 **VLESS URL Support**: Test connections directly from VLESS URLs
- 📁 **Config File Support**: Use existing Xray config files
- 🧩 **Fragment Mode**: Enable fragment for bypassing censorship
- 📊 **Real-time Statistics**: Live ping results with detailed stats
- 🎯 **Smart Port Management**: Automatic free port detection to avoid conflicts
- 🌈 **Colorful Output**: Beautiful colored terminal output
- ⚙️ **Environment Variables**: Customizable via environment variables
- 🛡️ **Config Validation**: Built-in Xray config validation

## 📦 Installation

### Prerequisites

- **Node.js** 16.0.0 or higher
- **Xray-core** installed and accessible

### Install via npm (Global)

```bash
npm install -g xping
```

### Manual Installation

```bash
git clone https://github.com/NabiKAZ/xping.git
cd xping
npm install
```

## 🚀 Usage

### Basic Usage

```bash
# Test with VLESS URL
xping "vless://uuid@server:port?security=tls&type=ws&path=/..."

# Test with config file
xping config.json

# Test with fragment mode (VLESS URL only)
xping "vless://..." --fragment

# Test with custom options
xping config.json --count 10 --delay 2000 --timeout 5000
```

### Command Line Options

```
Usage: xping [options] <input>

Arguments:
  input                 VLESS URL or xray config file path to test

Options:
  -v, --version         output the version number
  -f, --fragment        Enable fragment mode
  -d, --delay <ms>      Delay between pings in milliseconds (default: "1000")
  -t, --timeout <ms>    Connection timeout in milliseconds (default: "10000")
  -c, --count <number>  Number of pings to send (default: infinite)
  -h, --help            Display help for command
```

### Examples

```bash
# Basic ping test
xping "vless://abc123@example.com:443?security=tls&type=ws&path=/path"

# Test with fragment enabled
xping "vless://abc123@example.com:443?..." --fragment

# Test config file with limited count
xping config.json --count 5

# Test with custom timing
xping config.json --delay 500 --timeout 15000 --count 10

# Continuous testing (Ctrl+C to stop)
xping "vless://..."
```

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

## 📊 Output Example

```
✅ Config validation passed
📍 example.com:443 | my-server
🔒 tls | Network: ws | Protocol: vless
📝 Fragment: packets: tlshello, length: 100-200, interval: 10-20

[10:30:15] ✅ example.com:443 responded in 245ms
[10:30:16] ✅ example.com:443 responded in 198ms
[10:30:17] ❌ Request timeout
[10:30:18] ✅ example.com:443 responded in 267ms
^C
📊 === Statistics ===
📦 Sent: 4 | Received: 3 | Lost: 1 (25% loss)
⏱️  Min: 198ms | Max: 267ms | Avg: 237ms
🏁 Completed!
```

## 📋 Requirements

### System Requirements

- **Operating System**: Windows, macOS, Linux
- **Node.js**: Version 16.0.0 or higher
- **Xray-core**: Any recent version

### Dependencies

- `chalk`: For colored terminal output
- `commander`: For command-line interface
- `undici`: For HTTP requests with proxy support

## 🛠️ How It Works

1. **Input Detection**: Automatically detects whether input is a VLESS URL or config file
2. **Config Processing**: 
   - For VLESS URLs: Generates optimized Xray config
   - For config files: Processes in memory with free port assignment
3. **Validation**: Validates configuration using `xray -test`
4. **Proxy Setup**: Starts Xray with automatic port management
5. **Connection Testing**: Performs HTTP requests through the proxy
6. **Statistics**: Provides real-time and summary statistics

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

# 🎬 Demo Video

Coming soon! A demonstration and tutorial video for XPing will be available here.

---

# 💸 Donate

If you find this tool useful and would like to support its development:

- TON Wallet: `nabikaz.ton`

---

## 📄 License

This project is licensed under the **GNU GPLv3** - see the [LICENSE](LICENSE) file for details.

---

⭐ **Star this project if you find it useful!**
