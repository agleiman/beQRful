# beQRful
**QR Code Scanner, Generator, and Encryption Tool**

A comprehensive Python-based security tool that provides QR code scanning with malicious URL detection, QR code generation, and encrypted QR code creation for secure data transmission.

## Features

### **QR Code Security Scanner**
- **Real-time Detection**: Captures and decodes QR codes from your screen
- **Multi-API Security Checks**: Integrates with VirusTotal, Google Safe Browsing, and PhishTank
- **SSL Certificate Validation**: Verifies website certificate validity
- **Pattern Recognition**: Identifies suspicious keywords and file extensions
- **Result Logging**: Saves scan history to CSV files for future reference

### **QR Code Generator** 
- Generate custom QR codes from any text or URL
- Customizable filenames and output formats
- Instant preview of generated codes

### **Encrypted QR Codes**
- **AES-256 Encryption**: Military-grade encryption for sensitive data
- **HMAC-SHA256 Signatures**: Ensures data integrity and authenticity
- **Secure Key Generation**: Uses cryptographically secure random keys
- Perfect for transmitting confidential information

## Getting Started

### Prerequisites
```bash
pip install qrcode pillow pyzbar requests cryptography colorama
```

### Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/beqrful.git
cd beqrful
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python QRMain.py
```

## Usage

### Main Menu Options:
1. **Scan QR Codes** - Monitor screen for QR codes and analyze their safety
2. **Generate QR Code** - Create standard QR codes from your data
3. **Encrypt QR Code** - Generate secure, encrypted QR codes

### Scanner Operation:
- Press Enter to scan for QR codes on your screen
- Results are displayed in real-time with safety status
- All scans are automatically saved to `QR_info.csv`

### Security Analysis Results:
- **Safe** - URL passed all security checks
- **Malicious** - URL flagged by security APIs
- **Suspicious** - Contains potentially harmful patterns

## Architecture

### Core Components:
- **`QRMain.py`** - Main application interface and user interaction
- **`QRCodeScanner.py`** - Real-time QR detection and security analysis
- **`QRCodeGenerator.py`** - Standard QR code creation
- **`QRCodeEncrypt.py`** - Encrypted QR code generation with AES-256
- **`csv_writer.py`** - Data logging and file management

### Security APIs Used:
- **VirusTotal** - Comprehensive malware and threat detection
- **Google Safe Browsing** - Phishing and malware protection
- **SSL Certificate Validation** - HTTPS security verification

## Output Format

### Scanner Results:
```
| Timestamp             | Decoded QR Code               | Response         |
|----------------------|-------------------------------|------------------|
| 2025-04-27 14:30:15  | https://example.com           | Safe             |
| 2025-04-27 14:31:22  | https://malicious-site.com    | Malicious        |
```

### CSV Logging:
All scan results are automatically saved with timestamps for security auditing and analysis.

## Security Features

- **Multi-layered Analysis**: Combines pattern matching, API checks, and SSL validation
- **Thread-safe Processing**: Parallel security checks for faster analysis
- **Encrypted Data Storage**: Secure handling of sensitive QR code data
- **Integrity Verification**: HMAC signatures prevent data tampering

## Technical Specifications

- **Encryption**: AES-256-CBC with PKCS7 padding
- **Hashing**: HMAC-SHA256 for data integrity
- **Key Generation**: Cryptographically secure 256-bit keys
- **Image Processing**: PIL and pyzbar for QR detection
- **API Integration**: RESTful security service integration

## Requirements

- Python 3.7+
- Active internet connection (for security API checks)
- Screen capture permissions
- API keys for VirusTotal and Google Safe Browsing

## Use Cases

- **Cybersecurity Professionals**: Analyze QR codes for threats
- **Business Security**: Protect against malicious QR code attacks
- **Secure Communications**: Share encrypted data via QR codes
- **Personal Safety**: Verify QR code safety before scanning
