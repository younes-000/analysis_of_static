```markdown
# Static Malware Analyzer (Python)

This script performs **basic static analysis** on Windows executable files (`.exe` and `.dll`) using Python. It is intended for cybersecurity professionals, malware analysts, or students who want to better understand what an executable contains without executing it.

---

## Features

- Calculates common file hashes: MD5, SHA1, SHA256  
- Extracts printable ASCII strings from the binary  
- Parses PE (Portable Executable) file headers and sections  
- Detects common Indicators of Compromise (IOCs):  
  - IP addresses  
  - URLs  
  - File paths  

---

## Requirements

- Python 3.7 or higher  
- `pefile` library  

To install the required library:

```bash
pip install pefile
```

---

## How It Works

- The script takes the file path of a `.exe` or `.dll` as a command-line argument.  
- It calculates the file’s cryptographic hashes.  
- It extracts all printable ASCII strings of length 4 or more.  
- It parses the PE headers and section table using `pefile`.  
- It uses regex to find embedded IP addresses, URLs, and file paths in the strings.  

---

## Usage

```bash
python static_malware_analyzer.py <path_to_file>
```

**Example:**

```bash
python static_malware_analyzer.py OfficeSetup.exe
```

---

## Example Output

```bash
=== Hashes ===
{'MD5': '...', 'SHA1': '...', 'SHA256': '...'}

=== PE Info ===
{'entry_point': '0x...', 'image_base': '0x...', 'sections': [...]}

=== Strings (First 30) ===
['This program cannot be run in DOS mode.', '.text', ...]

=== Detected Indicators ===
{'ips': ['192.168.0.1'], 'urls': ['http://example.com'], 'file_paths': ['C:\\Users\\...']}
```

---
<img width="778" alt="image" src="https://github.com/user-attachments/assets/3842cdbc-d98a-4fe0-b7b2-19ae78677105" />


## Optional Improvements

- Add YARA rule scanning support  
- Export results to JSON or CSV  
- Build a GUI or web interface  
- Add entropy thresholding for suspicious sections  

---
