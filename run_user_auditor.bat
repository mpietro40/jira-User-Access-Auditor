@echo off
echo Starting Jira User Access Auditor...
echo.
echo This application will scan all Jira projects to identify external users
echo (users without your company email domain).
echo.
echo The application will be available at: http://localhost:5200
echo.
echo Press Ctrl+C to stop the application
echo.

cd /d "%~dp0"
python jira_user_auditor.py

pause