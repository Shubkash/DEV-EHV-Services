# DEV EHV Services — Supabase-ready deployment

## Local setup
1. Copy `.env.example` to `.env`.
2. Add your Supabase **shared pooler / session mode** `DATABASE_URL`.
3. Create a password hash with `npm run hash-password -- "a-long-unique-password"` and place its output in `ADMIN_PASSWORD_HASH`. This is mandatory in production; the legacy `ADMIN_PASSWORD` works only for local development during migration.
4. Set a long random `SESSION_SECRET` and your `ADMIN_USERNAME`.
5. Run `npm install`, then `npm start`.
6. Open `http://localhost:3000`.

The application automatically creates the enquiry and session tables on first successful database connection. A `GET /health` endpoint is available for host health checks.

## Free deployment
- Database: Supabase Free
- Node.js app: a free web-service host such as Render, subject to that provider's current free-tier limits.
- Add all values from `.env` as host environment variables. Never upload `.env`.

## Security
`DATABASE_URL`, `SESSION_SECRET`, password hashes, and SMTP credentials must stay private. Never use the sample values in `.env.example` in production.

## Operations

- Set the Render health-check path to `/health`.
- The admin dashboard is at `/admin`; it supports CSV export of enquiries.
- Back up the Supabase database regularly and define a retention policy before collecting customer data long term.
