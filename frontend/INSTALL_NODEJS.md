# Node.js Installation Guide for PhishGuard Frontend

## Step 1: Install Node.js

1. **Download Node.js:**
   - Go to: https://nodejs.org/
   - Click "Download for Windows" (LTS version recommended)
   - Run the downloaded installer (.msi file)

2. **Installation Options:**
   - ✅ Check "Add to PATH" (should be checked by default)
   - ✅ Install npm package manager (included)
   - ✅ Install additional tools for native modules (optional but recommended)

3. **Verify Installation:**
   - Open a NEW command prompt (important: restart after installation)
   - Type: `node --version`
   - Type: `npm --version`
   - Both should show version numbers

## Step 2: Install Frontend Dependencies

Once Node.js is installed:

```bash
cd C:\Users\shour\Downloads\PhishGuardClone\PhishGuard\frontend
npm install
```

This will install all dependencies including:
- @craco/craco (build tool)
- React and React DOM
- All UI components (Radix UI, Tailwind CSS)
- Development tools

## Step 3: Start the Application

```bash
npm start
```

The frontend will start on: http://localhost:3000

## Troubleshooting

**If "npm" is not recognized:**
- Restart your command prompt
- Reinstall Node.js and ensure "Add to PATH" is checked

**If installation is slow:**
- Try: `npm install --registry https://registry.npmjs.org/`

**If you get permission errors:**
- Run command prompt as Administrator

## Alternative: Use Yarn

If npm doesn't work, try Yarn:
```bash
npm install -g yarn
yarn install
yarn start
```
