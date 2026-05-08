# WebAuthn Demo

A minimal passwordless authentication demo using WebAuthn passkeys with an Express backend and a simple browser UI.

## What it does

- Registers a user with a passkey (`/api/register/*`)
- Authenticates a user with a passkey (`/api/login/*`)
- Persists users and credentials in `db.json`
- Exposes a protected profile endpoint (`/api/me`)
- Includes a negative tamper test in the client to demonstrate server-side verification

## Tech stack

- Node.js + Express
- `@simplewebauthn/server` and `@simplewebauthn/browser`
- `express-session`, `helmet`, `dotenv`

## Project structure

```text
public/        # Frontend HTML/CSS/JS
src/
  db/          # Data access
  routes/      # API route modules
  utils/       # Config, middleware, helpers, server startup
index.js       # App entrypoint
db.json        # Local JSON datastore
```

## Run locally with TLS (mkcert)

WebAuthn requires a secure origin. This project is expected to run on:

- `https://localhost:8443`
- `RP_ID=localhost`
- cert files in `certs/`

### 1) Clone the repository

```bash
git clone https://github.com/asifmMustafa/cse722-webauthn-project.git
cd cse722-webauthn-project
```

### 2) Install Node.js and dependencies

Install Node.js 20+ first, then run:

```bash
npm install
```

### 3) Configure environment

Create `.env` from `.env.example` and ensure these values are set:

```env
PORT=8443
RP_ID=localhost
ORIGIN=https://localhost:8443
USE_HTTPS=true
SESSION_SECRET=your-long-random-secret
```

### 4) Install and set up mkcert

#### macOS

```bash
brew install mkcert
mkcert -install
mkdir -p certs
mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost-cert.pem localhost 127.0.0.1 ::1
```

#### Windows (PowerShell)

Install mkcert with one package manager:

```powershell
choco install mkcert -y
```

or

```powershell
scoop install mkcert
```

Then generate certificates:

```powershell
mkcert -install
New-Item -ItemType Directory -Path certs -Force | Out-Null
mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost-cert.pem localhost 127.0.0.1 ::1
```

#### Linux

Install mkcert and NSS tools, then generate certificates.

Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y mkcert libnss3-tools
mkcert -install
mkdir -p certs
mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost-cert.pem localhost 127.0.0.1 ::1
```

Fedora:

```bash
sudo dnf install -y mkcert nss-tools
mkcert -install
mkdir -p certs
mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost-cert.pem localhost 127.0.0.1 ::1
```

Arch:

```bash
sudo pacman -S --needed mkcert nss
mkcert -install
mkdir -p certs
mkcert -key-file certs/localhost-key.pem -cert-file certs/localhost-cert.pem localhost 127.0.0.1 ::1
```

### 5) Start the app

```bash
npm run dev
```

or:

```bash
npm start
```

Open [https://localhost:8443](https://localhost:8443).