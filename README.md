# Vault — Password Manager Server

REST API backend for the Vault password manager. Handles authentication, encrypted credential storage, and vault management.

## Features

- 🔐 **JWT Authentication** — Secure login and registration with token expiry
- 🔒 **Zero-knowledge vault** — Client-side AES-GCM encryption; server stores ciphertext only
- 📥 **CSV Import** — Bulk import credentials with duplicate detection
- ✅ **Input Validation** — Request validation using express-validator
- 🧂 **Password Hashing** — bcrypt for auth verifier hashing

## Tech Stack

- **Runtime** — Node.js
- **Framework** — Express.js
- **Language** — TypeScript
- **Database** — MongoDB
- **ODM** — Mongoose
- **Authentication** — JSON Web Tokens (JWT)
- **Password Hashing** — bcrypt
- **Validation** — express-validator
- **Dev Server** — Nodemon

## Getting Started

### Prerequisites

- Node.js 18+
- MongoDB instance (local or Atlas)

### Installation

```bash
# Clone the repository
git clone https://github.com/ashwin586/vault-server.git
cd vault-server

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
```

### Environment Variables

Create a `.env` file in the root:

```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/vault
JWT_SECRET=generate_with_openssl_rand_hex_32
JWT_EXPIRES_IN=30m
COOKIE_SAMESITE=none
COOKIE_SECURE=true
```

`JWT_SECRET` must be at least 32 characters. Auth tokens are stored in an `httpOnly` cookie (`vault_access_token`) with `Secure` and `SameSite=None` so the cross-origin SPA can send them via `credentials: include`.

### Running the Server

```bash
# Development
npm run dev

# Production
npm run build
npm start
```

Server runs on [http://localhost:5000](http://localhost:5000).

## API Endpoints

### Auth

| Method | Endpoint     | Description                                      |
| ------ | ------------ | ------------------------------------------------ |
| GET    | `/auth/salt` | Fetch per-user vault KDF salt                    |
| POST   | `/login`     | Login with auth hash; sets httpOnly access cookie |
| POST   | `/register`  | Register with auth hash + salt                   |
| POST   | `/logout`    | Clear auth cookie and revoke current session     |

### Profile

| Method | Endpoint   | Description      |
| ------ | ---------- | ---------------- |
| GET    | `/profile` | Get user profile |

### Passwords

| Method | Endpoint                       | Description             |
| ------ | ------------------------------ | ----------------------- |
| GET    | `/profile/managePasswords`     | Get all saved passwords |
| POST   | `/profile/managePasswords`     | Add a new password      |
| PATCH  | `/profile/managePasswords/:id` | Update a password       |
| DELETE | `/profile/managePasswords/:id` | Delete a password       |
| POST   | `/profile/importCSV`           | Bulk import from CSV    |

## Project Structure

```
vault-server/
├── src/
│   ├── config/               # Database and CORS configuration
│   │   ├── cors.ts
│   │   └── mongoDB.ts
│   ├── controllers/          # Route handler logic
│   │   ├── authControllers.ts
│   │   └── profileControllers.ts
│   ├── middleware/           # JWT validation, input validation
│   │   ├── validateJWT.ts
│   │   └── validateRequest.ts
│   ├── models/               # Mongoose schemas
│   │   ├── users.ts
│   │   └── savedPasswords.ts
│   ├── routes/               # Express route definitions
│   │   └── routes.ts
│   ├── types/                # TypeScript interfaces
│   │   └── interface.ts
│   ├── utils/                # Helpers
│   │   └── passwordStrength.ts
│   ├── validators/           # express-validator schemas
│   │   └── validators.ts
│   └── app.ts                # Entry point
├── .env                      # Environment variables
├── .env.example              # Environment variables template
├── nodemon.json              # Nodemon configuration
├── package.json
└── tsconfig.json
```

Vault entry passwords are encrypted on the client. The API stores and returns opaque `password` ciphertext and `iv` only.

## Related

- [Vault Client](https://github.com/ashwin586/vault-client) — Next.js frontend
