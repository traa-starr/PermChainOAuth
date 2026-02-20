const fs = require('fs');
const path = require('path');

const rootDir = path.resolve(__dirname, '..');
const envPath = path.join(rootDir, '.env');
const envExamplePath = path.join(rootDir, '.env.example');

if (fs.existsSync(envPath)) {
  console.log('.env already exists. No changes made.');
  process.exit(0);
}

if (!fs.existsSync(envExamplePath)) {
  console.error('Missing .env.example in the repository root. Create .env.example, then run npm run setup again.');
  process.exit(1);
}

fs.copyFileSync(envExamplePath, envPath);
console.log('Created .env from .env.example.');
