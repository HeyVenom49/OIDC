# OIDC Auth Server

A small Express-based OpenID Connect style auth server built with Bun, TypeScript,
PostgreSQL, Drizzle ORM, and JWT signing.

## Setup

Install dependencies:

```bash
bun install
```

Create a `.env` file:

```env
PORT=8000
DATABASE_URL=postgresql://admin:admin@localhost:5432/oidc_auth
```

## Database

Start PostgreSQL with Docker:

```bash
docker compose up -d
```

Database connection details from `docker-compose.yml`:

```text
host: localhost
port: 5432
user: admin
password: admin
database: oidc_auth
```

Drizzle scripts:

```bash
bun run db:generate
bun run db:migrate
bun run db:studio
```

## Run

Start the dev server:

```bash
bun run dev
```

Type-check the project:

```bash
bun run typecheck
```

## Routes

Base URL:

```text
http://localhost:8000
```

Available routes:

```text
GET  /                                  Health message
GET  /health                            Server health check
GET  /.well-known/openid-configuration  OIDC discovery metadata
GET  /.well-known/jwks.json             Public signing keys
GET  /o/authenticate                    Sign-in page
GET  /signup.html                       Sign-up page
POST /o/authenticate/sign-up            Create user account
POST /o/authenticate/sign-in            Sign in and receive JWT
GET  /o/userinfo                        User profile, requires Bearer token
```

Example:

```bash
curl http://localhost:8000/.well-known/openid-configuration
```

## Notes

This project uses extensionless local imports in TypeScript, supported by
`moduleResolution: "bundler"` and the `tsx` dev runner. If you switch back to
compiled Node ESM output, relative imports usually need explicit `.js`
extensions.
