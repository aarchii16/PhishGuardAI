@echo off
echo Installing frontend dependencies...
echo.

REM Check if npm is available
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: npm is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo npm is available, installing dependencies...
npm install

if %errorlevel% neq 0 (
    echo.
    echo Installation failed. Trying with --force flag...
    npm install --force
)

if %errorlevel% neq 0 (
    echo.
    echo Installation still failed. Trying to clear cache and reinstall...
    npm cache clean --force
    del package-lock.json
    npm install
)

echo.
echo Installation complete! You can now run 'npm start' to start the development server.
pause
