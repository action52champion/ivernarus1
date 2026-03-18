const test = require('node:test');
const fs = require('fs');
const path = require('path');
const IVernarus1 = require('../src/IVernarus1.js');

const testKey = fs.readFileSync(path.join(__dirname, "testKey.txt"), { encoding: 'utf8' });

const msg = 'В 7:00 на вокзале мы с тобой встретимся. Буду в черной куртке с надписью Adidas.';

let keyPos = 1; 

test('test min deniability', (t) => {
    const enc = new IVernarus1(testKey, keyPos, { deniability : false });

    console.log("orig      :", msg);
    const encrypted = enc.encryptMessage(msg);
    console.log("encrypted :", encrypted);

    const decrypted = enc.decryptMessage(encrypted);
    console.log("decypted  :", decrypted);

    t.assert.strictEqual(msg, decrypted);
});


test('test max deniability', (t) => {
    const enc = new IVernarus1(testKey, keyPos, { deniability : true });

    console.log("orig      :", msg);
    const encrypted = enc.encryptMessage(msg);
    console.log("encrypted :", encrypted);

    const decrypted = enc.decryptMessage(encrypted);
    console.log("decypted  :", decrypted);

    t.assert.strictEqual(msg, decrypted);
});

test('test random checksum for short messages', (t) => {
    const enc = new IVernarus1(testKey, keyPos, { deniability : true });

    const shortMsg = '123';

    let checksumResults = {};
    let deniabilityTypeResults = {};
    for (let i = 0; i < 100; i++) {
        const encrypted = enc.encryptMessage(shortMsg);
        const decrypted = enc.decryptMessage(encrypted);

        const decodedData = enc.parseMessage(encrypted);      
        checksumResults[decodedData.checksum] = true;
        deniabilityTypeResults[decodedData.deniability] = true;

        t.assert.strictEqual(shortMsg, decrypted);
        t.assert.strictEqual(enc.lastError, null);
    }

    t.assert.ok(Object.keys(checksumResults).length > 10);
    t.assert.ok(Object.keys(deniabilityTypeResults).length > 10);
});

test('test non-random checksum for short messages', (t) => {
    const enc = new IVernarus1(testKey, keyPos, { deniability : true });

    const longMsg = '123567890';

    let results = {};
    let deniabilityTypeResults = {};

    for (let i = 0; i < 100; i++) {
        const encrypted = enc.encryptMessage(longMsg);
        const decrypted = enc.decryptMessage(encrypted);

        const decodedData = enc.parseMessage(encrypted);      
        results[decodedData.checksum] = true;
        deniabilityTypeResults[decodedData.deniability] = true;

        t.assert.strictEqual(longMsg, decrypted);
        t.assert.strictEqual(enc.lastError, null);
    }

    t.assert.ok(Object.keys(results).length === 1);
    t.assert.ok(Object.keys(deniabilityTypeResults).length > 10);
});
