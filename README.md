# DEV EHV Services — Supabase-ready deployment

## Local setup
1. Copy `.env.example` to `.env`.
2. Add your Supabase **shared pooler / session mode** `DATABASE_URL`.
3. Run `npm install`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

The application automatically creates the `enquiries` table on first successful database connection.

## Free deployment
- Database: Supabase Free
- Node.js app: a free web-service host such as Render, subject to that provider's current free-tier limits.
- Add all values from `.env` as host environment variables. Never upload `.env`.

## Security
`DATABASE_URL`, `SESSION_SECRET`, admin credentials, and SMTP credentials must stay private.
