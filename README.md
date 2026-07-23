<p align="center">
  <img src="https://raw.githubusercontent.com/niddle-hub/API-Vault/main/static/images/vault_icon.png" alt="API Vault" width="64" height="64">
  <h1 align="center">API Vault</h1>
  <p align="center">Secure local API key manager with encryption</p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#requirements">Requirements</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#security">Security</a>
  </p>
</p>

---

## Features

- 🔒 **AES-256-GCM Encryption** - All API keys are encrypted locally before storage
- 🔑 **PBKDF2HMAC Key Derivation** - Master password used to derive encryption key
- 🗃️ **SQLite Database** - Local storage with encrypted values only
- 🌙 **Modern Dark Theme** - Clean, accessible UI with neon accents
- 📱 **Responsive Design** - Works perfectly on desktop and mobile
- ⚡ **Zero-Knowledge Architecture** - Master password never leaves your device
- 🖼️ **Emoji/Favicon Support** - Custom vault icon per project

## Requirements

- Python 3.10 or higher
- Windows, macOS, or Linux
- Git (for cloning)

## Installation

### Windows

```powershell
# Clone the repository
git clone https://github.com/niddle-hub/API-Vault.git
cd API-Vault

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Run the application
python app.py
```

### macOS / Linux

```bash
# Clone the repository
git clone https://github.com/niddle-hub/API-Vault.git
cd API-Vault

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# Run the application
python app.py
```

## Usage

1. **First Launch** - On first run, API Vault will prompt you to create a master password. This password:
   - Must be at least 8 characters
   - Cannot be recovered if forgotten
   - Is never stored or transmitted anywhere

2. **Adding Keys** - Click the "Add" button and enter:
   - Service name (e.g., "OpenAI", "GitHub")
   - API key value

3. **Viewing Keys** - Keys are displayed masked by default (e.g., `abcd****1234`). Click the eye icon to reveal the full key.

4. **Editing Keys** - Click the edit icon to modify service name or key value.

5. **Deleting Keys** - Click the delete icon to remove a key permanently.

6. **Lock/Unlock** - Click "Lock" to secure the vault. You'll need your master password to access keys again.

## Configuration

Environment variables (optional):

| Variable | Default | Description |
|----------|---------|-------------|
| `API_VAULT_PORT` | `5000` | Port to run the server |
| `API_VAULT_SESSION_MINUTES` | `30` | Session timeout in minutes |
| `API_VAULT_DATABASE` | `keys.db` | Path to SQLite database |
| `API_VAULT_SECRET_KEY` | Auto-generated | Flask secret key |

## Security

API Vault uses multiple layers of security:

### Encryption
- **Fernet (AES-128-CBC)** - Primary encryption when `cryptography` package is installed
- **Windows DPAPI (AES-256-GCM)** - Fallback for Windows without cryptography package
- Keys are encrypted **before** being written to disk

### Storage
- Master password: **Never stored** - only used to derive encryption key
- Encrypted keys: Stored in `keys.db` SQLite database
- Session keys: **In-memory only** - cleared on server restart

### Recommendations
- Use a strong, unique master password
- Never share your `.app_secret` file
- Back up `keys.db` and `.app_secret` together for data recovery

## File Structure

```
API-Vault/
├── app.py              # Main Flask application
├── config.py           # Configuration and environment variables
├── crypto_utils.py     # Encryption/decryption utilities
├── session_store.py    # Session management
├── requirements.txt    # Python dependencies
├── templates/          # HTML templates
│   ├── base.html
│   ├── login.html
│   └── index.html
├── static/
│   ├── images/
│   │   └── vault_icon.png
│   ├── style.css
│   └── script.js
├── keys.db            # SQLite database (auto-created)
└── .app_secret        # Secret key (auto-created)
```

## Testing

```bash
python -m unittest -v test_app.py
```

## License

This project is licensed under the MIT License.

## Acknowledgments

This project was **completely created with AI assistance** using Claude Code by Anthropic.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/niddle-hub">niddle-hub</a>
</p>
