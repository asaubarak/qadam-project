@echo off
echo === Creating admin user in PRODUCTION ===
echo.
echo Please make sure you have set DATABASE_URL environment variable
echo to your Render PostgreSQL connection string!
echo.
echo Example: set DATABASE_URL=postgresql://username:password@host:port/database
echo.
pause

node create-admin-prod.js

echo.
echo === Done! ===
pause