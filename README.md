# **PyHashSum**

## ❓ **Overview**
**PyHashSum** is a powerful yet intuitive graphical tool designed to simplify the process of calculating and verifying checksums using various algorithms such as **MD5**, **SHA-1**, **SHA-256**, and **SHA-512**. With its clean and modern interface, the utility supports drag-and-drop functionality, copying checksum results to the clipboard, and saving results to text or JSON files. Additionally, it allows for folder scanning, making it ideal for batch processing multiple files.

Whether you're verifying file integrity, managing large datasets, or ensuring data security, PyHashSum has you covered!

---

## 💪 **Key Features**

- **Drag-and-Drop Support**: Simply drag files into the application to calculate their checksums.
- **Multiple Hash Algorithms**: Supports **MD5**, **SHA-1**, **SHA-256**, and **SHA-512** hash algorithms.
- **Copy to Clipboard**: Quickly copy any checksum result to the clipboard for easy sharing.
- **Save Results**: Save generated checksum results to **text**, **JSON**, or **CSV** files for record-keeping.
- **Verify Hashes**: Easily verify the integrity of files by comparing the generated hash with a provided hash.
- **Folder Scanning**: Scan entire folders (including subfolders) to calculate and display checksums for multiple files at once.
- **Save Folder Results**: Save the results of folder scans as **CSV**, **JSON**, or **text** files for easy documentation and further analysis.

---

## ✅ **Screenshots**

![Single File Checksum](https://github.com/user-attachments/assets/26f076c8-558c-435e-8ff3-6f4eab59ec54)

*Generating checksums for a single file.*

![Folder Scan](https://github.com/user-attachments/assets/a81e4cbc-ed0d-49f6-b447-b644efb41444)

*Scanning a folder and generating checksums for all files.*

![Save Results](https://github.com/user-attachments/assets/d60d5e27-ecd6-4b23-ba74-3f586cbe6dd9)

*Saving results to a file for future reference.*

---

## 🔽 **Installation**

### Install via pip (Recommended)
```bash
pip install pyhashsum
```

### Download Latest Release
Alternatively, you can download the pre-build executable from [GitHub Releases](https://github.com/oop7/pyhashsum/releases).

---

## 💻 **Usage**

Run the application from the command line:
```bash
pyhashsum
```

---

## ⚙️ **Development Setup**

If you'd like to contribute or modify the source code, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/oop7/pyhashsum.git
   ```

2. Navigate to the project directory:
   ```bash
   cd pyhashsum
   ```

3. Run the application:
   ```bash
   python main.py
   ```

---

## 📦 **PyPI Package**

The package is available on PyPI:  
[![PyPI version](https://badge.fury.io/py/pyhashsum.svg)](https://pypi.org/project/pyhashsum/)

---

## 🛠️ **How to Use**

### **Single File Checksum Generation**

1. **Open File**: Click the "Browse" button to select a file, or drag and drop the file into the designated area.
2. **Generate Checksums**: The tool will automatically calculate and display the **MD5**, **SHA-1**, **SHA-256**, and **SHA-512** checksums.
3. **Copy Checksums**: Use the "Copy" buttons to quickly copy any checksum to the clipboard.
4. **Save Results**: Click the "Save Report" button to save the checksum results to a **text** or **JSON** file.
5. **Verify Hash**: Enter a hash in the "Hash" field and click "Verify" to compare it against the calculated checksum.

---

### **Folder Scan**

1. **Select Folder**: Click the "Browse Folder" button to choose the folder you want to scan.
2. **Options**: Opt to include subfolders and hidden files if necessary.
3. **Scan Folder**: The utility will scan the selected folder and compute the checksums for all files within.
4. **View Results**: The results are displayed in a table, showing file names, paths, and their corresponding checksums.
5. **Save Folder Results**: Click "Save Folder Results" to save the scan results as **CSV**, **JSON**, or **text** files.

---

## 📜 **License**

This project is licensed under the **MIT License**. See the [LICENSE](https://github.com/oop7/MD5-SHA-Checksum-Utility/blob/main/LICENSE) file for more details.

---

## 📙 **Contributing**

We welcome contributions from the community! If you'd like to contribute, feel free to:

- Open an issue to report bugs or suggest features.
- Submit a pull request with improvements or bug fixes.
