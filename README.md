# KF8 backend login fix

This is a clean Node/Express backend starter that matches the frontend login contract:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/balance`
- `GET /api/health`

## Why this fixes the current login problem

The frontend is being opened from an Android `content://` page. Browsers commonly send that page an origin of `null`. This server explicitly allows the `null` origin and accepts JSON POST requests to `/api/auth/login`.

It also:
- stores passwords as bcrypt hashes;
- enforces globally unique usernames and emails in PostgreSQL;
- accepts username OR email at login;
- returns a JWT and a `user` object;
- supports Render's `PORT` and `DATABASE_URL`.

## Render setup

1. Create a PostgreSQL database in Render (or use your existing PostgreSQL database).
2. Create a Web Service from this project/repository.
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variables:
   - `DATABASE_URL` = your PostgreSQL connection string
   - `JWT_SECRET` = a long random secret
   - `ADMIN_USERNAME` = your admin username
   - `ADMIN_EMAIL` = your admin email
   - `ADMIN_PASSWORD` = your admin password
6. Deploy.
7. Open `https://YOUR-SERVICE.onrender.com/` and confirm it says `KF8 Backend is running`.
8. Open `/api/health` and confirm `database: connected`.

Do not put real passwords or database credentials in GitHub. Use Render environment variables.

## Important

This ZIP is a replacement/starter backend, not a patch of your private existing backend, because the existing backend source code was not provided. Before replacing an existing production backend, back up its database and code.
