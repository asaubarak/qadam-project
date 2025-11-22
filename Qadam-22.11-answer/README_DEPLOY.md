Deploy notes for Render
======================

This repository contains a single Node + Vite web application (frontend in `client/`, backend in `server/`). The build produces `dist/public` (static assets) and `dist/index.js` (server bundle) which serves both API and static files.

Quick Render setup
------------------

1. Go to https://dashboard.render.com and create a new **Web Service**.
2. Connect your GitHub repository `marktrost/EProject` and select branch `main`.
3. Use these settings:
   - Environment: Node
   - Build Command: `npm ci && npm run build`
   - Start Command: `npm run start`
   - Health check path: `/`

Required environment variables (add as Secrets / Environment in Render):

- `DATABASE_URL` — PostgreSQL connection string (required)
- `SESSION_SECRET` — random secret for session cookies
- `PUBLIC_OBJECT_SEARCH_PATHS` — comma-separated public object paths (project-specific)
- `PRIVATE_OBJECT_DIR` — local/private object directory path (used by server)
- `VAPID_PUBLIC` and `VAPID_PRIVATE` — (if you use web-push)
- any SMTP or third-party keys your app needs

Database migrations
-------------------

If you need to apply SQL migrations before switching traffic, do a safe backup of the DB and then run the SQL from `migrations/20251007_remove_proctoring.sql` on the production DB. You can use `psql` or a DB admin tool. If you use Drizzle CLI in production, run `npx drizzle-kit push` with `DATABASE_URL` set.

Notes and troubleshooting
------------------------

- Render sets `PORT` automatically; the server reads `process.env.PORT` and binds to `0.0.0.0` by default.
- If you get build errors on Render, check deploy logs and ensure secrets (especially `DATABASE_URL`) are set for build or runtime steps if required.
- For local production testing on Windows PowerShell use:

```powershell
$env:PORT="3001"; $env:NODE_ENV="production"; node dist/index.js
```

If you want, I can also create a small `server/start.js` wrapper to make `npm run start` cross-platform.

Security
--------
- Do not commit secrets. Use Render's Environment -> Secrets to store sensitive values.

After deploy
-----------

- Open the assigned Render URL and run the smoke tests: register, start a test, submit answers, view review mode.
- Check logs in Render for errors and fix as necessary.

If you'd like, I can proceed to:
- Create a `server/start.js` wrapper and update `package.json` (optional)
- Run through the Render UI steps with you and paste ready-to-use values for env vars
- Prepare migration commands and sample `psql` lines for applying the proctoring removal SQL
