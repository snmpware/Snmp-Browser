# SNMP Browser

Professional SNMP browser with modern GUI for network device discovery and monitoring.

![License](https://img.shields.io/badge/license-GPL%20v3-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)

## 🚀 Features

- **SNMPv1/v2c/v3 Support** - Complete SNMP protocol support with authentication and encryption
- **Modern GUI Interface** - Intuitive graphical interface built with tkinter
- **Cross-Platform** - Native support for Windows and Linux systems
- **Network Device Discovery** - Browse and explore SNMP-enabled devices
- **Real-time Monitoring** - Live monitoring of device status and performance metrics
- **OID Tree Browser** - Navigate through SNMP MIB structures
- **Export Capabilities** - Save results and configurations
- **Portable Executable** - Single-file deployment, no installation required

## 📥 Download

Download the latest pre-built executable from the [Releases](https://github.com/JustVugg/Snmp-Browser/releases) page.

**Windows**: `SNMP_Browser_v3.exe` - Just download and run!  

## 🛠️ Installation from Source

### Prerequisites
```bash
pip install -r requirements.txt
```

**Required packages:**
- `cryptography` - Encryption support for SNMPv3
- `psutil` - System utilities
- `snmpy` - SNMP library (from [JustVugg/snmpy](https://github.com/JustVugg/snmpy))
- `tkinter` - GUI framework (usually included with Python)

### Running from Source
```bash
git clone https://github.com/yourusername/snmp-browser-v3.git
cd snmp-browser-v3
pip install -r requirements.txt
python snmpflowV3.py
```

## 🏗️ Building Executables

### Windows
```bash
pyinstaller --onefile --windowed --icon=icon.png ^
    --add-data="icon.png;." ^
    --hidden-import=cryptography ^
    --hidden-import=psutil ^
    --hidden-import=snmpy ^
    --collect-all=snmpy ^
    --collect-all=cryptography ^
    --collect-all=psutil ^
    --name=SNMP_Browser_v3 snmpflowV3.py
```

### Linux/Ubuntu
```bash
pyinstaller --onefile --windowed --icon=icon.png \
    --add-data="icon.png:." \
    --hidden-import=cryptography \
    --hidden-import=psutil \
    --hidden-import=snmpy \
    --collect-all=snmpy \
    --collect-all=cryptography \
    --collect-all=psutil \
    --name=SNMP_Browser_v3 snmpflowV3.py
```

The executable will be created in the `dist/` directory.

## 💻 System Requirements

- **Operating System**: Windows 10+ or Ubuntu 18.04+
- **Python**: 3.7 or higher (for source installation)
- **Memory**: 256 MB RAM minimum
- **Network**: Access to SNMP-enabled devices

## 🚦 Quick Start

1. Launch the application
2. Enter target device IP address
3. Configure SNMP version and credentials
4. Click "Connect" to start browsing
5. Navigate through the OID tree to explore device information

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 Requirements.txt
```
cryptography>=3.4.8
psutil>=5.8.0
git+https://github.com/JustVugg/snmpy.git
pyinstaller>=4.10
```

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **SNMP Library**: [snmpy](https://github.com/JustVugg/snmpy) by [JustVugg](https://github.com/JustVugg)
- **GUI Framework**: [tkinter](https://docs.python.org/3/library/tkinter.html)
- **Executable Packaging**: [PyInstaller](https://pyinstaller.readthedocs.io/)

---

**Note**: This software is provided as-is under GPL v3 license. For commercial support or custom development, please open an issue.
