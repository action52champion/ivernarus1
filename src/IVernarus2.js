// IVernarus2 - вторая мажорная версия протокола.
//
// Отличия от v1:
//
// 1. Многобайтная гамма без модульного биаса.
//    Каждый шифруемый символ потребляет 4 ключевых символа (печатные ASCII 32..126).
//    Они трактуются как цифры в base-95 → uint32 в диапазоне [0, 95^4 = 81_450_625).
//    Из этого числа через rejection sampling получаем равномерное значение
//    по модулю длины алфавита. Биас становится строго нулевым.
//
// 2. Зашифрованный 80-битный auth-тег вместо HMAC.
//    Целостность и подлинность защищаются 80-битной контрольной суммой
//    (первые 10 байт SHA-256(plaintext + ":" + keyPos)), которая кодируется
//    16 символами keyAlphabet через base-33/BigInt и шифруется вместе с
//    плейнтекстом. Отдельного auth-ключа нет.
//
//    Для OTP-шифра это эквивалентно (или сильнее) усечённому HMAC: модель
//    стойкости информационно-теоретическая - подделка требует угадать 80 бит
//    в шифротексте без знания keystream. Вычислительная мощь атакующего
//    значения не имеет.
//
// 3. Метаданные (denflag + auth-тег) ВСЕГДА шифруются в keyAlphabet (33 символа)
//    независимо от режима deniability. Получатель расшифровывает их раньше тела,
//    узнаёт режим, потом строит алфавит для тела.
//
// 4. В сообщении в открытом виде остаётся ТОЛЬКО keyPos (4 символа).
//    Скрыть её нельзя - без неё получатель не сможет вывести keystream.
//
// 5. Несовместимо с v1. Ключи v2 имеют заголовок IVN2: в файле.

module.exports = class IVernarus2 {

    alphanumAlphabets = [
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ',
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
    ];

    deniableAlphabet = ' -,.<>!?/\\+=_)(*&^%$#@`|№;:\n';

    keyAlphabet = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя';

    keyPosLength = 4;
    keystreamBytesPerChar = 4;
    authTagBytes = 10;       // 80-бит SHA-256-truncated тег
    authTagChars = 16;       // 33^16 ≈ 2^80.2 - влезает с небольшим запасом
    metadataLength = 1 + 16; // denflag + 16 символов auth-тега в keyAlphabet

    lastError = null;
    lastKeyPos = 0;

    constructor(keyData, keyPos = 0, options = {}) {
        this.keyData = keyData;
        this.keyPos = keyPos;
        this.deniability = !!(options && options.deniability);
        this.lastError = null;
    }

    // ── вспомогательные ────────────────────────────────────────────────────

    secureRandomInt(maxExclusive) {
        if (!this._crypto) {
            if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
                this._crypto = globalThis.crypto;
            } else if (typeof require === 'function') {
                try { this._crypto = require('crypto').webcrypto; } catch (e) {}
            }
            if (!this._crypto || !this._crypto.getRandomValues) {
                throw new Error('No CSPRNG available');
            }
        }
        const arr = new Uint32Array(1);
        const cutoff = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
        while (true) {
            this._crypto.getRandomValues(arr);
            if (arr[0] < cutoff) return arr[0] % maxExclusive;
        }
    }

    textToCodePoints(text) {
        const out = [];
        for (const c of text) out.push(c);
        return out;
    }

    buildAlphabets(deniability) {
        let alphabets = this.alphanumAlphabets.slice();
        if (deniability) {
            alphabets.push(this.deniableAlphabet);
            alphabets = [alphabets.join('')];
        }
        return alphabets;
    }

    // ── гамма ──────────────────────────────────────────────────────────────

    // 4 ключевых символа (печатный ASCII 32..126) → uint32 в base-95.
    readKeyUint32(keyPos) {
        let v = 0;
        for (let i = 0; i < this.keystreamBytesPerChar; i++) {
            const code = this.keyData.charCodeAt(keyPos + i);
            v = v * 95 + (code - 32);
        }
        return v;
    }

    // Очередное значение гаммы [0, alphabetLength) с rejection sampling.
    // Двигает this.keyPos на keystreamBytesPerChar (или больше при отказе).
    nextKeystream(alphabetLength) {
        const max = Math.pow(95, this.keystreamBytesPerChar);  // 81_450_625
        const cutoff = Math.floor(max / alphabetLength) * alphabetLength;
        while (true) {
            // Защита от отрицательного/нечислового keyPos (например после
            // подделки ciphertext с битым keyPos-чанком). Иначе charCodeAt
            // негативного индекса = NaN, и цикл крутил бы псевдо-rejections
            // до выхода за длину - это freeze браузера на секунды.
            if (!Number.isInteger(this.keyPos) || this.keyPos < 0 ||
                this.keyPos + this.keystreamBytesPerChar > this.keyData.length) {
                throw new Error('IVernarus2: ключ закончился или keyPos невалиден');
            }
            const v = this.readKeyUint32(this.keyPos);
            this.keyPos += this.keystreamBytesPerChar;
            if (v < cutoff) return v % alphabetLength;
            // редчайший случай (у нас 95^4 ≈ 81M, отбрасываем хвост,
            // не делящийся нацело на длину алфавита)
        }
    }

    // ── кодирование служебных полей ────────────────────────────────────────

    encodeKeyPos(pos) {
        let s = '';
        let n = pos;
        const base = this.keyAlphabet.length;
        while (true) {
            s = this.keyAlphabet[n % base] + s;
            n = Math.floor(n / base);
            if (n === 0) break;
        }
        while (s.length < this.keyPosLength) s = this.keyAlphabet[0] + s;
        return s;
    }

    // Возвращает >=0 при успехе, -1 если хоть один символ не в keyAlphabet.
    // Без валидации indexOf=-1 загрязнял бы число и keyPos уходил в негатив.
    decodeKeyPos(chars) {
        let n = 0;
        const base = this.keyAlphabet.length;
        for (const c of chars) {
            const d = this.keyAlphabet.indexOf(c);
            if (d === -1) return -1;
            n = n * base + d;
        }
        return n;
    }

    encodeDeniability(deniability) {
        const half = Math.floor(this.keyAlphabet.length / 2);
        const range = deniability
            ? this.keyAlphabet.substring(half)
            : this.keyAlphabet.substring(0, half);
        return range[this.secureRandomInt(range.length)];
    }

    decodeDeniability(char) {
        const half = Math.floor(this.keyAlphabet.length / 2);
        return this.keyAlphabet.indexOf(char) >= half;
    }

    // SubtleCrypto для SHA-256. Доступен в браузере (window.crypto.subtle)
    // и в Node 19+ (globalThis.crypto.subtle).
    _subtle() {
        if (this._subtleCache) return this._subtleCache;
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            this._subtleCache = globalThis.crypto.subtle;
        } else if (typeof require === 'function') {
            try { this._subtleCache = require('crypto').webcrypto.subtle; } catch (e) {}
        }
        if (!this._subtleCache) throw new Error('No SubtleCrypto available for SHA-256');
        return this._subtleCache;
    }

    // 80-битный auth-тег от плейнтекста + keyPos. Привязка к keyPos нужна
    // чтобы атакующий не мог взять валидное сообщение с одной keyPos и
    // подставить чужой keyPos в открытой части - проверка не сошлась бы.
    async computeAuthTag(plaintext, keyPos) {
        const data = new TextEncoder().encode(plaintext + ':' + keyPos);
        const hash = await this._subtle().digest('SHA-256', data);
        return new Uint8Array(hash).slice(0, this.authTagBytes);
    }

    // 10 байт тега → 16 символов keyAlphabet (base-33). 33^16 ≈ 2^80.2,
    // так что любое 80-битное значение влезает.
    bytesToTagChars(bytes) {
        let n = 0n;
        for (const b of bytes) n = (n << 8n) | BigInt(b);
        const base = BigInt(this.keyAlphabet.length);
        let result = '';
        for (let i = 0; i < this.authTagChars; i++) {
            result = this.keyAlphabet[Number(n % base)] + result;
            n = n / base;
        }
        return result;
    }

    // Константно-временное сравнение строк одинаковой длины.
    // Без short-circuit, чтобы тайминг не выдавал позицию первой разницы.
    _constantTimeStringEqual(a, b) {
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) {
            diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return diff === 0;
    }

    findAlphabet(c, alphabets) {
        for (const alpha of alphabets) {
            const pos = alpha.indexOf(c);
            if (pos !== -1) return { alpha, pos };
        }
        return null;
    }

    // Вставить keyPos сразу за последним alphanum-символом шифротекста
    // (как в v1 - этот приём устойчив к хвостовым не-алфавитным символам).
    appendKeyPos(encrypted, keyPosEncoded) {
        const points = this.textToCodePoints(encrypted);
        const alphanumChars = this.alphanumAlphabets.join('');
        let appendPos = -1;
        for (let i = points.length - 1; i >= 0; i--) {
            if (alphanumChars.indexOf(points[i]) !== -1) {
                appendPos = i;
                break;
            }
        }
        return points.slice(0, appendPos + 1).join('') +
               keyPosEncoded +
               points.slice(appendPos + 1).join('');
    }

    // ── основные операции ──────────────────────────────────────────────────

    async encryptMessage(srcMsg) {
        const startKeyPos = this.keyPos;
        const bodyAlphabets = this.buildAlphabets(this.deniability);

        // Метаданные: denflag + 80-битный auth-тег. Шифруются вместе с телом.
        // tag привязан к keyPos чтобы атакующий не смог переставить ту же
        // полезную нагрузку под другую keyPos в открытой части.
        const denflagChar = this.encodeDeniability(this.deniability);
        const tagBytes = await this.computeAuthTag(srcMsg, startKeyPos);
        const tagChars = this.bytesToTagChars(tagBytes);
        const composed = denflagChar + tagChars + srcMsg;

        // Первые metadataLength символов - метаданные, шифруются ВСЕГДА
        // через keyAlphabet (33 chars) независимо от режима. Остальное - тело
        // в bodyAlphabets.
        const points = this.textToCodePoints(composed);
        let encrypted = '';
        let metadataDoneCount = 0;

        for (let i = 0; i < points.length; i++) {
            const c = points[i];

            if (metadataDoneCount < this.metadataLength) {
                const pos = this.keyAlphabet.indexOf(c);
                if (pos === -1) {
                    // Не должно случаться - метаданные гарантированно в keyAlphabet
                    throw new Error('IVernarus2: metadata char not in keyAlphabet');
                }
                const k = this.nextKeystream(this.keyAlphabet.length);
                encrypted += this.keyAlphabet[(pos + k) % this.keyAlphabet.length];
                metadataDoneCount++;
                continue;
            }

            const found = this.findAlphabet(c, bodyAlphabets);
            if (found) {
                const k = this.nextKeystream(found.alpha.length);
                encrypted += found.alpha[(found.pos + k) % found.alpha.length];
            } else {
                encrypted += c;  // не алфавит → проброс
            }
        }

        const keyPosEncoded = this.encodeKeyPos(startKeyPos);
        const result = this.appendKeyPos(encrypted, keyPosEncoded);

        this.lastKeyPos = this.keyPos;
        return result;
    }

    // Извлекает keyPos из сообщения без расшифровки.
    // Нужно для replay-защиты: проверить keyPos ДО того как тратить ключ.
    peekKeyPos(srcMsg) {
        const points = this.textToCodePoints(srcMsg);
        const alphanumChars = this.alphanumAlphabets.join('');
        let lastAlphanumIdx = -1;
        for (let i = points.length - 1; i >= 0; i--) {
            if (alphanumChars.indexOf(points[i]) !== -1) {
                lastAlphanumIdx = i;
                break;
            }
        }
        if (lastAlphanumIdx < this.keyPosLength - 1) return null;
        const keyPosChars = points.slice(lastAlphanumIdx - this.keyPosLength + 1, lastAlphanumIdx + 1);
        const kp = this.decodeKeyPos(keyPosChars);
        // -1 = в keyPos-чанке оказались символы вне keyAlphabet (повреждение/подделка)
        if (kp < 0) return null;
        return kp;
    }

    async decryptMessage(srcMsg) {
        this.lastError = null;
        const points = this.textToCodePoints(srcMsg);
        const alphanumChars = this.alphanumAlphabets.join('');

        // Найти keyPos: последние keyPosLength alphanum-символов перед хвостом
        let lastAlphanumIdx = -1;
        for (let i = points.length - 1; i >= 0; i--) {
            if (alphanumChars.indexOf(points[i]) !== -1) {
                lastAlphanumIdx = i;
                break;
            }
        }
        if (lastAlphanumIdx < this.keyPosLength - 1) {
            this.lastError = 'Сообщение слишком короткое или повреждено.';
            return '';
        }
        const keyPosStartIdx = lastAlphanumIdx - this.keyPosLength + 1;
        const keyPosChars = points.slice(keyPosStartIdx, lastAlphanumIdx + 1);
        const keyPos = this.decodeKeyPos(keyPosChars);

        // Жёсткая валидация keyPos чанка - только символы keyAlphabet и в
        // пределах ключевого пространства. Иначе подделанный ciphertext
        // мог бы загнать nextKeystream в долгий цикл или out-of-bounds read.
        if (keyPos < 0 || keyPos + this.keystreamBytesPerChar > this.keyData.length) {
            this.lastError = 'Невалидная позиция ключа в сообщении.';
            return '';
        }

        // Тело = всё кроме чанка keyPos
        const bodyPoints = points.slice(0, keyPosStartIdx)
            .concat(points.slice(lastAlphanumIdx + 1));

        // Расшифровка
        this.keyPos = keyPos;

        const decrypted = [];
        let metadataDoneCount = 0;
        let metadataChars = '';
        let bodyAlphabets = null;

        for (let i = 0; i < bodyPoints.length; i++) {
            const c = bodyPoints[i];

            if (metadataDoneCount < this.metadataLength) {
                const pos = this.keyAlphabet.indexOf(c);
                if (pos === -1) {
                    // В метаданных НЕ должно быть не-keyAlphabet символов.
                    // Если есть - сообщение повреждено, прерываем.
                    this.lastError = 'Метаданные повреждены: неожиданный символ.';
                    return '';
                }
                const k = this.nextKeystream(this.keyAlphabet.length);
                const dpos = (pos - k + this.keyAlphabet.length) % this.keyAlphabet.length;
                const dc = this.keyAlphabet[dpos];
                decrypted.push(dc);
                metadataChars += dc;
                metadataDoneCount++;
                if (metadataDoneCount === this.metadataLength) {
                    // Декодируем denflag и строим алфавиты для тела
                    const denflag = this.decodeDeniability(metadataChars[0]);
                    bodyAlphabets = this.buildAlphabets(denflag);
                }
                continue;
            }

            const found = this.findAlphabet(c, bodyAlphabets);
            if (found) {
                const k = this.nextKeystream(found.alpha.length);
                const dpos = (found.pos - k + found.alpha.length) % found.alpha.length;
                decrypted.push(found.alpha[dpos]);
            } else {
                decrypted.push(c);
            }
        }

        // Метаданные: 1 символ denflag + N символов auth-тега
        const receivedTagChars = metadataChars.substring(1);
        const originalPoints = decrypted.slice(this.metadataLength);
        const originalMsg = originalPoints.join('');

        // Сверяем auth-тег константно по времени, чтобы не дать атакующему
        // брутить тег char-by-char через тайминг (обычное !== short-circuit'ит
        // на первой разнице - утечка ~5 бит за запрос).
        const expectedTagBytes = await this.computeAuthTag(originalMsg, keyPos);
        const expectedTagChars = this.bytesToTagChars(expectedTagBytes);
        if (!this._constantTimeStringEqual(expectedTagChars, receivedTagChars)) {
            this.lastError = 'Auth-тег не сошёлся: сообщение повреждено или подделано.';
        }

        this.lastKeyPos = this.keyPos;
        return originalMsg;
    }
};
