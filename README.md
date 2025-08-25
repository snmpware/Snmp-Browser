<div align="center">
  <img src="icon.png" alt="SNMP Browser Professional Logo" width="128" height="128">
</div>

# SNMP Browser Professional

Advanced SNMP browser with modern GUI for network device discovery, monitoring, trap management, and performance analysis.

![License](https://img.shields.io/badge/license-GPL%20v3-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)
![Version](https://img.shields.io/badge/version-4.0-green.svg)

## 🚀 Features

### Core Capabilities
- **SNMPv1/v2c/v3 Support** - Complete SNMP protocol support with authentication and encryption
- **Modern GUI Interface** - Professional tabbed interface built with tkinter
- **Cross-Platform** - Native support for Windows and Linux systems
- **Network Device Discovery** - Browse and explore SNMP-enabled devices
- **Real-time Monitoring** - Live monitoring with auto-refresh capabilities
- **Advanced MIB Browser** - Navigate through SNMP MIB structures with value display

### 🆕 Features
- **Trap Manager** - Complete trap receiver and sender in one interface
  - Receive SNMP traps on configurable ports
  - Send test traps for all versions (v1/v2c/v3)
  - Pre-configured trap templates (Cold Start, Link Down, UPS alerts, etc.)
  - Real-time trap visualization with detailed decoding
- **Performance Monitor** - Track and analyze SNMP operations
  - Query response times and success rates
  - Memory and CPU usage monitoring
  - Performance graphs (with matplotlib)
  - Export performance metrics
- **Batch Operations** - Query multiple hosts simultaneously
  - Parallel execution with configurable workers
  - Progress tracking and result aggregation
  - Export results to CSV/JSON
- **MIB Compiler Support** - Load and parse custom MIB files
  - Built-in UPS MIB definitions (RFC 1628)
  - Search MIB definitions
  - Custom vendor MIB support
- **Profile Manager** - Save and manage multiple configurations
  - Quick switch between different devices/credentials
  - Encrypted password storage
  - Import/Export profiles

### Security & Enterprise Features
- **Encrypted Credential Storage** - Secure password management
- **Memory Limits** - Configurable result and memory limits
- **Comprehensive Logging** - Rotating log files with multiple levels
- **Multi-format Export** - CSV, JSON, HTML, XML, TXT
- **Dashboard Monitoring** - Pin important OIDs for continuous monitoring

## 📥 Download

Download the latest pre-built executable from the [Releases](https://github.com/JustVugg/Snmp-Browser/releases) page.

**Windows**: `SNMP_Browser_Professional_v4.exe` - Just download and run!  
**Linux**: `SNMP_Browser_Professional_v4` - Make executable with `chmod +x`

## 🛠️ Installation from Source

### Prerequisites
```bash
pip install -r requirements.txt
```

**Required packages:**
- `cryptography>=41.0.0` - Encryption support for SNMPv3 and credential storage
- `psutil>=5.9.0` - System monitoring and resource management
- `snmpy>=2.1.0` - Advanced SNMP library with trap support
- `Pillow>=10.0.0` - Image processing for logo display
- `matplotlib>=3.5.0` - Performance graphs (optional but recommended)

### Optional Dependencies
```bash
# For performance graphs
pip install matplotlib

# For advanced MIB parsing
pip install pysmi
```

### Running from Source
```bash
git clone https://github.com/yourusername/snmp-browser-professional.git
cd snmp-browser-professional
pip install -r requirements.txt
python snmp_browser_professional.py
```

## 🏗️ Building Executables

### Windows
```bash
pyinstaller --onefile --windowed --icon=icon.ico ^
    --add-data="icon.png;." ^
    --add-data="icon.ico;." ^
    --hidden-import=cryptography ^
    --hidden-import=psutil ^
    --hidden-import=snmpy ^
    --hidden-import=PIL ^
    --hidden-import=matplotlib ^
    --collect-all=snmpy ^
    --collect-all=cryptography ^
    --collect-all=psutil ^
    --name=SNMP_Browser_Professional_v4 snmp_browser_professional.py
```

### Linux/Ubuntu
```bash
pyinstaller --onefile --windowed --icon=icon.png \
    --add-data="icon.png:." \
    --hidden-import=cryptography \
    --hidden-import=psutil \
    --hidden-import=snmpy \
    --hidden-import=PIL \
    --hidden-import=matplotlib \
    --collect-all=snmpy \
    --collect-all=cryptography \
    --collect-all=psutil \
    --name=SNMP_Browser_Professional_v4 snmp_browser_professional.py
```

## 💻 System Requirements

- **Operating System**: Windows 10/11 or Ubuntu 20.04+
- **Python**: 3.7 or higher (for source installation)
- **Memory**: 512 MB RAM minimum (1 GB recommended)
- **Network**: Access to SNMP-enabled devices
- **Permissions**: Admin/root for trap receiver on port 162

## 🚦 Quick Start Guide

### Basic SNMP Browsing
1. Launch the application
2. Enter target device IP address
3. Select SNMP version (1, 2c, or 3)
4. Configure credentials (community string or SNMPv3 user)
5. Click "Avvia Scansione" to discover OIDs
6. Browse results in the main tab

### Using Trap Manager
1. Go to "Trap Manager" tab
2. **Receiver**: Click "Avvia Receiver" (requires admin for port 162)
3. **Sender**: Configure destination and select trap type
4. Click "📤 Invia Trap" to send

### Batch Operations
1. Menu → Tools → "Operazioni Batch"
2. Enter multiple host IPs (one per line)
3. Specify OID to query
4. Click "Esegui" for parallel execution

### Performance Monitoring
1. Go to "Performance" tab
2. View real-time metrics after operations
3. Export data for analysis

## 🔧 Configuration Files

The application creates several configuration files:
- `snmp_browser_config.json` - Main configuration
- `snmp_browser_saved.json` - Dashboard items
- `snmp_profiles.json` - Saved connection profiles
- `.SNMPBrowser_key` - Encryption key (keep secure!)
- `logs/` - Directory containing rotating log files

## 📊 Supported Operations

### SNMP Operations
- GET - Retrieve single OID value
- GET MULTIPLE - Retrieve multiple OIDs efficiently
- GET NEXT - Get next OID in tree
- GET BULK - Bulk retrieval (v2c/v3)
- SET - Modify writable OIDs
- WALK - Traverse MIB subtree

### Trap Types Supported
- Standard: Cold Start, Warm Start, Link Up/Down, Authentication Failure
- UPS-specific: Battery Low, On Battery, Overload, Temperature
- Custom enterprise traps with configurable varbinds

## 🔐 Security Features

- **SNMPv3 Full Support**: All authentication and privacy protocols
- **Encrypted Storage**: Passwords encrypted at rest using Fernet
- **Memory Protection**: Secure deletion of sensitive data
- **Access Control**: Configurable timeouts and retry limits
- **Audit Trail**: Comprehensive logging of all operations

## 📝 MIB Support

### Built-in MIBs
- RFC 1213 - MIB-II
- RFC 1628 - UPS MIB
- Enterprise MIBs: APC (318), Eaton (534), CyberPower (3808)

### Loading Custom MIBs
1. Menu → Tools → "Carica MIB"
2. Select .mib or .txt file
3. OID names automatically available

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Clone with submodules
git clone --recursive https://github.com/yourusername/snmp-browser-professional.git

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📄 Requirements.txt
```
cryptography>=41.0.0
psutil>=5.9.0
Pillow>=10.0.0
matplotlib>=3.5.0
git+https://github.com/JustVugg/snmpy.git@v2.1.0
```

### Development Requirements
```
pytest>=7.0.0
black>=22.0.0
flake8>=4.0.0
pyinstaller>=5.0
```

## 🐛 Troubleshooting

### Common Issues

**"Permission denied" on trap receiver**
- Run as administrator (Windows) or with sudo (Linux)
- Or change trap port to >1024 (e.g., 1162)

**"Module not found" errors**
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- For matplotlib issues: `pip install matplotlib --upgrade`

**High memory usage**
- Adjust limits in Settings → Limiti
- Clear cache with Tools → Pulisci Cache

**SNMPv3 discovery fails**
- Check firewall settings
- Verify SNMPv3 credentials
- Try manual Engine ID discovery

## 📈 Performance Tips

- Use SNMPv2c or v3 for bulk operations (10x faster)
- Enable "Scansione Estesa" only when needed
- Set appropriate timeout values for your network
- Use profiles for quick device switching
- Limit walk operations to specific subtrees

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **SNMP Library**: [snmpy](https://github.com/JustVugg/snmpy) by [JustVugg](https://github.com/JustVugg)
- **GUI Framework**: [tkinter](https://docs.python.org/3/library/tkinter.html)
- **Icons**: Material Design Icons
- **Executable Packaging**: [PyInstaller](https://pyinstaller.readthedocs.io/)

## 📞 Support

- **Bug Reports**: Open an issue with debug logs attached
- **Feature Requests**: Use the issue template
- **Security Issues**: Contact privately first

---

**SNMP Browser Professional** - Enterprise-grade SNMP management tool with modern GUI 🚀

*Making network monitoring simple, powerful, and secure!*
