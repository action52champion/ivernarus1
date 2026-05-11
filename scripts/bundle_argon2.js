// Собираем argon2id из @noble/hashes в один self-contained файл src/argon2id.js
// Запускается отдельно (нечасто). Результат коммитится в репозиторий.
// Не требует node_modules в обычной сборке html.

const path = require('path');
const fs = require('fs');
const esbuild = require('esbuild');

const tmp = path.join(__dirname, '..', '.argon2-entry.js');
fs.writeFileSync(tmp, `
import { argon2id } from '@noble/hashes/argon2.js';
globalThis.argon2id = argon2id;
`);

esbuild.buildSync({
    entryPoints: [tmp],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: ['es2020'],
    minify: true,
    legalComments: 'inline',
    outfile: path.join(__dirname, '..', 'src', 'argon2id.js'),
});

fs.unlinkSync(tmp);
console.log('Built src/argon2id.js (' + (fs.statSync(path.join(__dirname, '..', 'src', 'argon2id.js')).size / 1024).toFixed(1) + 'KB)');
