module.exports = class IVernarus1 {

    alphanumAlphabets = [
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ',
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
    ];

    deniableAlphabet = ' -,.<>!?/\\+=-_)(*&^%$#@`|№;:';

    checksumMessageMinLen = 5;

    keyAlphabet = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя';
    keyPosLength = 4;

    encoders = [];

    lastKeyPos = 0;

    lastError = null;

    constructor(keyData, keyPos = 0, options = {}) {
        this.keyData = keyData;
        this.keyPos = keyPos;

        if (options.deniability !== null) {
            this.deniability = options.deniability;
        }

        this.buildAlphabets(this.deniability);
    }

    buildAlphabets(deniability) {
        this.alphabets = this.alphanumAlphabets;

        if (deniability) {
            this.alphabets.push(this.deniableAlphabet);
            this.alphabets = [ this.alphabets.join("") ];
        }

        for (let i = 0; i < this.alphabets.length; i++) {
            this.encoders[i] = this.alphabets[i] + this.alphabets[i];
        }

        this.encodableChars = this.alphabets.join("");
    }

    textToUtf8Array(text) {
        let out = [];
        const iterator = text[Symbol.iterator]();
        while (true) {
            const charIter = iterator.next();
            if (charIter.done)
                break;
            out.push(charIter.value);
        }

        return out;
    }

    encryptChunk(key, msg) {
        const iterator = msg[Symbol.iterator]();

        let outMsg = '';

        let keyPos = 0;
        while (true) {
            const charIter = iterator.next();
            if (charIter.done)
                break;

            const char = charIter.value;
            let replaced = false;
            for (let i = 0; i < this.alphabets.length; i++) {
                const charPos = this.alphabets[i].indexOf(char);
                if (charPos != -1) {
                    const encoderPos = charPos + key[keyPos].charCodeAt(0) % this.alphabets[i].length;
                    outMsg += this.encoders[i][ encoderPos ];
                    keyPos++;
                    replaced = true;
                }
            }

            if (! replaced) {
                outMsg += char;
            }
        }

        return outMsg;
    }

    decryptChunk(key, msg) {
        const iterator = msg[Symbol.iterator]();

        let outMsg = '';

        let keyPos = 0;
        while (true) {
            const charIter = iterator.next();
            if (charIter.done)
                break;

            const char = charIter.value;
            let replaced = false;
            for (let i = 0; i < this.alphabets.length; i++) {
                const charPos = this.alphabets[i].indexOf(char);
                if (charPos != -1) {
                    const encoderPos = this.alphabets[i].length + charPos - ( key[keyPos].charCodeAt(0) % this.alphabets[i].length );
                    outMsg += this.encoders[i][ encoderPos ];
                    keyPos++;
                    replaced = true;
                }
            }

            if (! replaced) {
                outMsg += char;
            }
        }

        return outMsg;
    }

    // закодировать int четырьмя русскими буквами
    encodeKeyPos(pos) {
        let encodedKeyPos = '';
        let slidePos = pos;
        while (true) {
            const nextDigit = this.keyAlphabet[slidePos % this.keyAlphabet.length];
            slidePos = Math.floor(slidePos / this.keyAlphabet.length);

            encodedKeyPos = nextDigit + encodedKeyPos;

            if (slidePos === 0)
                break;
        }

        while ( encodedKeyPos.length < this.keyPosLength)
            encodedKeyPos = this.keyAlphabet[0] + encodedKeyPos;

        return encodedKeyPos;
    }

    // сумма считается только для тех символов, которые могут быть зашифрованы
    // для коротких сообщений сумма считается рандомно, чтобы усложнить подбор
    calculateChecksum(msg) {
        const msgData = this.textToUtf8Array(msg);

        let checksum = 0;

        for (let i = 0; i < msgData.length; i++) {
            const charPos = this.encodableChars.indexOf(msgData[i]);
            if (charPos != -1) {
                checksum += charPos;
            }
        }

        if (msgData.length < this.checksumMessageMinLen) {
            checksum += Math.floor(Math.random() * this.keyAlphabet.length);
        }

        checksum = checksum % this.keyAlphabet.length;
        checksum = this.keyAlphabet[checksum];

        return checksum;
    }

    // добавить данные для декодирования в уже зашифрованное сообщение
    appendDecoderData(msg, extraValues) {
        
        const msgChars = this.textToUtf8Array(msg);

        let appendPos = 0;

        const neededChars = this.alphabets.join("");
        for (let i = msgChars.length; i > 0; i--) {
            if (neededChars.indexOf(msgChars[i]) !== -1) {
                appendPos = i;
                break;
            }
        }

        let result = msgChars.slice(0, appendPos+1);
        result = result.concat(extraValues);
        result = result.concat(msgChars.slice(appendPos+1));

        return result.join("");
    }

    encodeDeniability(deniabilityType) {
        const border = Math.floor(this.keyAlphabet.length / 2);

        let encoded = '';
        if (deniabilityType) {
            const denialAphabet = this.keyAlphabet.substring(border);
            encoded = denialAphabet[ Math.floor( Math.random() * denialAphabet.length) ];
        }
        else {
            const noDenialAphabet = this.keyAlphabet.substring(0, border);
            encoded = noDenialAphabet[ Math.floor( Math.random() * noDenialAphabet.length) ];
        }
        return encoded;
    }

    decodeDeniability(rawDeniabilityVal) {
        const border = Math.floor(this.keyAlphabet.length / 2);
        const deniability = this.keyAlphabet.substring(0, border).indexOf(rawDeniabilityVal) == -1 ? true : false;
        return deniability;
    }

    // разбить сообщение на служебную часть и сам текст
    parseMessage(msg) {
        const neededChars = this.alphabets.join("");
        
        let keyDataEndPos = 0;
        let msgChars = this.textToUtf8Array(msg);

        for (let i = msgChars.length - 1; i > 0; i--) {
            if (neededChars.indexOf(msgChars[i]) !== -1) {
                keyDataEndPos = i;
                break;
            }            
        }

        const keyPosData = [];
        for (let i = 0; i < this.keyPosLength; i++) {
            keyPosData.push(msgChars[keyDataEndPos + 1 + i - this.keyPosLength]);
        }

        const checksum = msgChars[keyDataEndPos - this.keyPosLength];
        const deniability = msgChars[keyDataEndPos - this.keyPosLength - 1];

        const indexBeforeEncoderData = keyDataEndPos - this.keyPosLength - 1;
        const message = msgChars.slice(0, indexBeforeEncoderData ).join("") + msgChars.slice(keyDataEndPos+1).join("");

        return {
            deniability: deniability,
            message : message,
            checksum: checksum,
            keypos: keyPosData
        };
            
    }

    decodeKeyPos(keyPosData) {
        const iterator = keyPosData[Symbol.iterator]();

        let decimal = 0;
        const base = this.keyAlphabet.length;
        for (let i = 0; i < this.keyPosLength; i++) {
            const digit = this.keyAlphabet.indexOf(iterator.next().value);
            const power = this.keyPosLength - 1 - i;
            decimal += digit * Math.pow(base, power);
        }

        return decimal;
    }

    encryptMessage(srcMsg) {
        const keyPiece = this.keyData.substring(this.keyPos, this.keyPos + srcMsg.length);

        let outMsg = this.encryptChunk(keyPiece, srcMsg);
        
        const keyPosEncoded = this.encodeKeyPos(this.keyPos);
        const checksum = this.calculateChecksum(srcMsg);

        outMsg = this.appendDecoderData(outMsg, [this.encodeDeniability(this.deniability), checksum, keyPosEncoded]);
        this.lastKeyPos = this.keyPos + srcMsg.length;
        
        return outMsg;
    }

    decryptMessage(srcMsg) {
        const decodedData = this.parseMessage(srcMsg);
        const keyPos = this.decodeKeyPos(decodedData.keypos);
        const keyPiece = this.keyData.substring(keyPos, keyPos + decodedData.message.length);
        const deniability = this.decodeDeniability(decodedData.deniability);
        this.buildAlphabets(deniability);

        let decodedMessage = this.decryptChunk(keyPiece, decodedData.message);
        if ((decodedData.message.length > this.checksumMessageMinLen) && (this.calculateChecksum(decodedMessage) !== decodedData.checksum)) {
            this.lastError = 'Контрольная сумма не сходится. Сообщение было повреждено.';
        }
        this.lastKeyPos = keyPos + decodedMessage.length;

        return decodedMessage;
    }

};
