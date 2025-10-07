# Indotex License Admin Panel (Flask)

This repo contains the Admin Panel and License API for Indotex ScrapUserAgent.

Endpoints:
- GET / -> health
- POST /login -> license login API (username/password/device)
- Admin UI: /admin/login -> login with ADMIN_USER/ADMIN_PASS

Deployment (Railway):
1. Push this repo to GitHub.
2. Create a Railway project -> Deploy from GitHub.
3. Set environment variables in Railway dashboard:
   - ADMIN_USER (e.g. admin)
   - ADMIN_PASS (strong password)
   - APP_SECRET (random long string)
   - USERS_FILE (optional, default users.json)
4. Start command: `python admin_server.py`

Security notes:
- Change ADMIN_PASS and APP_SECRET before deploy.
- For persistence across redeploys use a database (SQLite/Postgres) instead of users.json in container.
