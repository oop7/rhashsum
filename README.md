# Rust Hash Sum

Rust Hash Sum is a high-performance, cross-platform desktop application for calculating and verifying file checksums. It's built with a Rust backend for maximum speed and a React frontend for a modern user experience. The application is packaged with Tauri, ensuring a small bundle size and native performance.

<img width="802" height="632" alt="image" src="https://github.com/user-attachments/assets/1655b4b1-4028-4284-ba00-3106ce48453e" />

## Features

- **High-Performance Hashing**: The Rust backend is optimized for speed, using memory-mapped files and up to 8 concurrent worker threads for rapid processing of large files and directories.
- **Multiple Algorithms**: Supports a wide range of hashing algorithms:
  - MD5
  - SHA-1
  - SHA-256
  - SHA-512
  - BLAKE3 (multi-threaded)
  - xxHash3
- **Advanced Folder Scanning**: Recursively scan entire folders with real-time progress tracking, file counters, and the ability to cancel ongoing operations.
- **Improved Result Visualization**: Folder scan results are rendered as interactive cards with per-algorithm copy buttons for quick access.
- **Drag and Drop**: Easily drag and drop files into the application to start hashing immediately.
- **Hash Verification**: Verify a file's integrity with strict input validation and instant comparison against known hashes.
- **GPG Authenticity Checks**: Dedicated tab for verifying detached GPG signatures with fingerprint validation.
- **Enhanced Save Reports**: Export results to JSON or highly customizable CSV files (toggle headers, exclude empty fields).
- **Persistent Window State**: Automatically remembers your window size and position between sessions for a seamless experience.
- **Cross-Platform**: Native performance on Windows, macOS, and Linux.
- **Light and Dark Mode**: Fully responsive theme support.

## Technologies Used

- **Backend**: [Rust](https://www.rust-lang.org/)
- **Frontend**: [React](https://reactjs.org/) with [TypeScript](https://www.typescriptlang.org/)
- **Framework**: [Tauri](https://tauri.app/)
- **UI**: [Material-UI](https://mui.com/)

## Installation and Usage

### Prerequisites

- [Node.js](https://nodejs.org/) and [npm](https://www.npmjs.com/)
- [Rust](https://www.rust-lang.org/tools/install)

### Running the Application

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/oop7/rhashsum.git
    cd rhashsum
    ```

2.  **Install the frontend dependencies:**
    ```bash
    npm install
    ```

3.  **Run the Tauri development server:**
    ```bash
    npm run tauri dev
    ```

### Building the Application

To build the application for your platform, run:

```bash
npm run tauri build
```

The executable will be located in `src-tauri/target/release/`.

## Contributing

Contributions are welcome! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull request.

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add some feature'`).
5.  Push to the branch (`git push origin feature/your-feature`).
6.  Open a pull request.

## Support

If you find this project useful, you can support development here:

- GitHub Sponsors: [https://github.com/sponsors/oop7](https://github.com/sponsors/oop7)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
