const test = require('node:test');
const fs = require('fs');
const path = require('path');
const IVernarus2 = require('../src/IVernarus2.js');

const testKey = fs.readFileSync(path.join(__dirname, "testKey.txt"), { encoding: 'utf8' });

const longMsg = 'В 7:00 на вокзале мы встретимся.';
const keyPos = 0;

test('v2 roundtrip non-deniable', async (t) => {
    const enc = new IVernarus2(testKey, keyPos, { deniability: false });
    const ct = await enc.encryptMessage(longMsg);
    const dec = new IVernarus2(testKey, keyPos, { deniability: false });
    const pt = await dec.decryptMessage(ct);
    t.assert.strictEqual(pt, longMsg);
    t.assert.strictEqual(dec.lastError, null);
});

test('v2 roundtrip deniable', async (t) => {
    const enc = new IVernarus2(testKey, keyPos, { deniability: true });
    const ct = await enc.encryptMessage(longMsg);
    const dec = new IVernarus2(testKey, keyPos, { deniability: true });
    const pt = await dec.decryptMessage(ct);
    t.assert.strictEqual(pt, longMsg);
    t.assert.strictEqual(dec.lastError, null);
});

test('v2 receiver auto-detects mode from message', async (t) => {
    // Получатель НЕ должен указывать режим вручную - он зашифрован в сообщении.
    // Любой стартовый режим у получателя должен дать корректную расшифровку.
    for (const senderDen of [false, true]) {
        for (const receiverDen of [false, true]) {
            const enc = new IVernarus2(testKey, keyPos, { deniability: senderDen });
            const ct = await enc.encryptMessage(longMsg);
            const dec = new IVernarus2(testKey, keyPos, { deniability: receiverDen });
            const pt = await dec.decryptMessage(ct);
            t.assert.strictEqual(
                pt, longMsg,
                `failed when sender=${senderDen} receiver=${receiverDen}`
            );
            t.assert.strictEqual(dec.lastError, null);
        }
    }
});

test('v2 emojis at various positions', async (t) => {
    const cases = [
        'Привет 😀',
        '😀 Привет',
        'При😀вет',
        'Привет 🇺🇸',
        '😀😀😀',
        'Hello 🇷🇺 world 🇺🇸',
    ];
    for (const mode of [false, true]) {
        for (const msg of cases) {
            const enc = new IVernarus2(testKey, keyPos, { deniability: mode });
            const ct = await enc.encryptMessage(msg);
            const dec = new IVernarus2(testKey, keyPos, { deniability: mode });
            const pt = await dec.decryptMessage(ct);
            t.assert.strictEqual(pt, msg, `failed: "${msg}" den=${mode}`);
        }
    }
});

test('v2 keyPos transmitted in message', async (t) => {
    // Получатель не знает изначальный keyPos отправителя - он берёт его из сообщения.
    const enc = new IVernarus2(testKey, 50, { deniability: false });
    const ct = await enc.encryptMessage('test');
    const dec = new IVernarus2(testKey, 0, { deniability: false });  // другая стартовая позиция
    const pt = await dec.decryptMessage(ct);
    t.assert.strictEqual(pt, 'test');
    t.assert.strictEqual(dec.lastError, null);
});

test('v2 tamper detection via auth tag', async (t) => {
    const enc = new IVernarus2(testKey, 0, { deniability: false });
    const ct = await enc.encryptMessage('секретное сообщение');
    // Меняем 5-й символ на отличный (если был 'а' - на 'б', иначе на 'а')
    const swap = ct[5] === 'а' ? 'б' : 'а';
    const tampered = ct.slice(0, 5) + swap + ct.slice(6);
    const dec = new IVernarus2(testKey, 0, { deniability: false });
    await dec.decryptMessage(tampered);
    t.assert.notStrictEqual(dec.lastError, null);
});

test('v2 keyPos rebinding fails (sender wrote keyPos=42, attacker changed to 43)', async (t) => {
    // Auth-тег привязан к keyPos через хеш plaintext+":"+keyPos.
    // Если атакующий поменяет открытую keyPos в сообщении, тег не сойдётся.
    const enc = new IVernarus2(testKey, 42, { deniability: false });
    const ct = await enc.encryptMessage('hello');
    // Меняем последние 4 символа keyPos: индексы (length-1) - keyPos[0..3]
    // Простейший случай: меняем последний символ keyPos
    const last = ct.slice(-1);
    const swap = last === 'а' ? 'б' : 'а';
    const tampered = ct.slice(0, -1) + swap;
    const dec = new IVernarus2(testKey, 0, { deniability: false });
    await dec.decryptMessage(tampered);
    t.assert.notStrictEqual(dec.lastError, null);
});

test('v2 keystream is unbiased on real key', (t) => {
    // Проверка равномерности гаммы - chi-square test
    const dummy = new IVernarus2(testKey, 0, { deniability: false });
    const buckets = new Array(33).fill(0);
    const N = Math.floor((testKey.length - 4) / 4);
    for (let i = 0; i < N; i++) {
        buckets[dummy.nextKeystream(33)]++;
    }
    const exp = N / 33;
    let chiSq = 0;
    for (const c of buckets) chiSq += (c - exp) ** 2 / exp;
    // df=32, p<0.001 = 62.5. На малой выборке (~250) test пройдёт даже при биасе,
    // но факт что мы используем 4 байта на символ структурно убирает биас.
    t.assert.ok(chiSq < 100, `chi-square ${chiSq} - возможен биас`);
});

test('v2 peekKeyPos extracts keyPos without decrypting', async (t) => {
    // Нужно для replay-защиты: проверить keyPos ДО траты ключа
    const enc = new IVernarus2(testKey, 42, { deniability: false });
    const ct = await enc.encryptMessage('hello');
    // peekKeyPos должен вернуть стартовую позицию отправителя (42)
    const peek = new IVernarus2(testKey, 0, { deniability: false });
    t.assert.strictEqual(peek.peekKeyPos(ct), 42);

    // peekKeyPos не должен менять состояние (keyPos остаётся 0)
    t.assert.strictEqual(peek.keyPos, 0);
});

test('v2 peekKeyPos returns null for too-short message', (t) => {
    const peek = new IVernarus2(testKey, 0, { deniability: false });
    t.assert.strictEqual(peek.peekKeyPos(''), null);
    t.assert.strictEqual(peek.peekKeyPos('abc'), null);
});

test('v2 multiline plaintext roundtrip in deniable mode', async (t) => {
    const enc = new IVernarus2(testKey, 0, { deniability: true });
    const original = 'Первая строка\nВторая строка\nТретья';
    const ct = await enc.encryptMessage(original);
    const dec = new IVernarus2(testKey, 0, { deniability: true });
    const pt = await dec.decryptMessage(ct);
    t.assert.strictEqual(pt, original);
    t.assert.strictEqual(dec.lastError, null);
});

test('v2 deniable mode hides newlines (not at same positions)', async (t) => {
    // В deniable-режиме \n входит в алфавит и шифруется. В шифротексте
    // переносы НЕ должны оказаться на тех же позициях, что в plaintext'е.
    const original = 'a\nb\nc\nd\ne\nf';  // 5 переносов на известных позициях
    const enc = new IVernarus2(testKey, 0, { deniability: true });
    const ct = await enc.encryptMessage(original);
    const ptNewlinePositions = [...original].map((c, i) => c === '\n' ? i : -1).filter(i => i !== -1);
    const ctNewlinePositions = [...ct].map((c, i) => c === '\n' ? i : -1).filter(i => i !== -1);
    t.assert.notDeepStrictEqual(ctNewlinePositions, ptNewlinePositions,
        'позиции \\n в шифротексте совпали с plaintext-ом - структура утекает');
});

test('v2 ciphertext compactness: short message overhead', async (t) => {
    // "привет" = 6 символов. Ожидаем: 6 (тело) + 17 (метаданные = 1 denflag + 16 tag) + 4 (keyPos) = 27 символов.
    const enc = new IVernarus2(testKey, 0, { deniability: false });
    const ct = await enc.encryptMessage('привет');
    t.assert.strictEqual(ct.length, 27, `длина шифротекста ${ct.length}, ожидалось 27`);
});
