# PhishGuard Setup Guide

## Prerequisites

### 1. Install Node.js
- Download Node.js from: https://nodejs.org/
- Install the LTS version (includes npm)
- Restart your terminal/command prompt after installation

### 2. Install Python (for backend)
- Download Python 3.8+ from: https://python.org/
- Make sure to check "Add Python to PATH" during installation

## Setup Instructions

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python server.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm start
```

## Troubleshooting

### If npm commands don't work:
1. Verify Node.js installation: `node --version`
2. Verify npm installation: `npm --version`
3. If not found, reinstall Node.js and restart terminal

### Alternative Frontend Setup (if npm fails):
1. Use the install-deps.bat script: `.\install-deps.bat`
2. Or try yarn: `yarn install && yarn start`

### Common Issues:
- **'react-scripts' not recognized**: Run `npm install` first
- **'craco' not recognized**: Scripts have been updated to use react-scripts
- **Permission errors**: Run terminal as administrator
- **Network issues**: Try `npm install --registry https://registry.npmjs.org/`

## Project Structure
```
PhishGuard/
├── backend/          # Python FastAPI server
│   ├── server.py     # Main API server
│   ├── ml_models_real.py  # ML models
│   └── requirements.txt   # Python dependencies
├── frontend/         # React application
│   ├── src/          # React source code
│   ├── package.json  # Node.js dependencies
│   └── install-deps.bat  # Dependency installer
└── SETUP_GUIDE.md   # This file
```

## Running the Application
1. Start backend: `cd backend && python server.py`
2. Start frontend: `cd frontend && npm start`
3. Access application at: http://localhost:3000
