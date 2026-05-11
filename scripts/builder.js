const fs = require('fs');
const path = require('path');
const cryptoMod = require('crypto');

const srcDir  = path.join(__dirname, '..', 'src');
const distDir = path.join(__dirname, '..', 'dist');

function loadClass(filename) {
    const data = fs.readFileSync(path.join(srcDir, filename), 'utf8');
    return data.substring(data.indexOf('class '));
}

const cipherJs   = loadClass('IVernarus2.js');
const themesData = fs.readFileSync(path.join(srcDir, 'themes.js'), 'utf8');
const argon2Js   = fs.readFileSync(path.join(srcDir, 'argon2id.js'), 'utf8');

// SHA-256 хеши всех inline-script блоков для CSP. Без unsafe-inline в
// script-src браузер выполнит только скрипты с известным хешем -
// инжект через XSS работать не будет.
function computeCSPScriptHashes(html) {
    const re = /<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g;
    const hashes = [];
    let m;
    while ((m = re.exec(html)) !== null) {
        const body = m[1];
        if (body.trim() === '') continue;
        const hash = cryptoMod.createHash('sha256').update(body, 'utf8').digest('base64');
        hashes.push(`'sha256-${hash}'`);
    }
    return hashes.join(' ');
}

let html = fs.readFileSync(path.join(srcDir, 'template.html'), 'utf8');
html = html.replace('###INCLUDE_IVERNARUS###', cipherJs);
html = html.replace('###INCLUDE_THEMES###',     themesData);
html = html.replace('###INCLUDE_ARGON2###',     argon2Js);
html = html.replace('###CSP_SCRIPT_HASHES###',  computeCSPScriptHashes(html));

if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });
fs.writeFileSync(path.join(distDir, 'ivernarus2.html'), html, 'utf8');
console.log('Built dist/ivernarus2.html (' + (html.length / 1024).toFixed(1) + ' KB)');
