import { cpSync, mkdirSync, rmSync } from 'node:fs';
rmSync('dist', { recursive: true, force: true });
mkdirSync('dist/server', { recursive: true });
mkdirSync('dist/.openai/drizzle', { recursive: true });
cpSync('worker/index.js', 'dist/server/index.js');
cpSync('worker/qrcode.js', 'dist/server/qrcode.js');
cpSync('.openai/hosting.json', 'dist/.openai/hosting.json');
cpSync('.openai/drizzle', 'dist/.openai/drizzle', { recursive: true });
