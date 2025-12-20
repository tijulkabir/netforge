# NetForge

**NetForge** is an industry-grade CyberChef clone designed with a "dark hacker" aesthetic and advanced functionality. It features a unique stealth mode that disguises the application as a standard calculator until a secret access code is entered.

## Features

- **Stealth Mode**: The application launches as a fully functional calculator.
- **Secure Access**: Enter the secret code `1971-2024` and press `=` to unlock the full suite of tools.
- **Comprehensive Toolset**:
  - **Data Format**: Base64, Hex, Binary, Decimal converters.
  - **Encryption/Encoding**: ROT13, URL Encode/Decode, HTML Entity, XOR.
  - **Hashing**: MD5, SHA1, SHA256, SHA512.
  - **Code Tidy**: JSON/XML Beautify & Minify.
  - **Networking**: IP Defang/Refang.
  - **Utils**: String manipulation and analysis tools.
- **Recipe System**: Chain multiple operations together to process data in complex ways.
- **Modern UI**: specialized "dark hacker" theme with glassmorphism and animations.

## Tech Stack

- **Frontend Framework**: [React](https://react.dev/)
- **Build Tool**: [Vite](https://vitejs.dev/)
- **Styling**: Vanilla CSS with modern features (Variables, Flexbox/Grid)
- **Crypto Library**: [Crypto-JS](https://github.com/brix/crypto-js)
- **Icons**: [Lucide React](https://lucide.dev/)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/tijulkabir/netforge.git
   cd netforge
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

## Usage

1. **Start the development server**:
   ```bash
   npm run dev
   ```

2. **Open the application**:
   Navigate to `http://localhost:5173` (or the URL provided in the terminal).

3. **Unlock NetForge**:
   - You will see a calculator.
   - Enter `1971-2024`.
   - Press `=`.
   - The NetForge interface will appear.

## Building for Production

To create a production build:

```bash
npm run build
```

The output will be in the `dist` directory.

## License

[MIT](LICENSE)
