const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

// заменяем bodyParser на встроенный express.json()
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 8080;
const IMAGE_PATH = path.join(__dirname, 'image.png');
const CHUNK_SIZE = 32 * 1024; // 32 KB per chunk


// Читаем файл в память (для demo). Для больших файлов используйте стримы.
if (!fs.existsSync(IMAGE_PATH)){
console.error('Put an image named image.png in project root');
process.exit(1);
}
const IMAGE_BUFFER = fs.readFileSync(IMAGE_PATH);
const TOTAL_CHUNKS = Math.ceil(IMAGE_BUFFER.length / CHUNK_SIZE);


// Серверный ECDH (P-256)
const serverECDH = crypto.createECDH('prime256v1');
serverECDH.generateKeys();
const serverPublic = serverECDH.getPublicKey(); // Buffer (uncompressed)


// Вспомог: HKDF (sha256) simple
function hkdf(keyMaterial, salt, info, length = 32) {
// Using Node's built-in HKDF via hkdfSync in newer Node isn't guaranteed; implement HKDF-Extract+Expand
const prk = crypto.createHmac('sha256', salt).update(keyMaterial).digest();
let prev = Buffer.alloc(0);
const output = [];
let i = 0;
while (Buffer.concat(output).length < length) {
i += 1;
const hmac = crypto.createHmac('sha256', prk);
hmac.update(prev);
hmac.update(info);
hmac.update(Buffer.from([i]));
prev = hmac.digest();
output.push(prev);
}
return Buffer.concat(output).slice(0, length);
}


app.get('/session-init', (req, res) => {
// возвращаем публичный ключ сервера и информацию о чанках
res.json({
serverPublic: serverPublic.toString('base64'),
chunkSize: CHUNK_SIZE,
totalChunks: TOTAL_CHUNKS
});
});


app.post('/get-chunk', (req, res) => {
try {
const { clientPublic, chunkIndex } = req.body;
if (typeof clientPublic !== 'string') return res.status(400).json({error: 'clientPublic required'});
const clientPubBuf = Buffer.from(clientPublic, 'base64');


// Вычисляем общий секрет
const sharedSecret = serverECDH.computeSecret(clientPubBuf);


// Derive AES-256-GCM key via HKDF using session salt = first 16 bytes of shared
const salt = Buffer.alloc(16, 0);
sharedSecret.copy(salt, 0, 0, Math.min(16, sharedSecret.length));
const aesKey = hkdf(sharedSecret, salt, Buffer.from('protected-image'), 32); // 32 bytes => AES-256


// Получаем байты нужного чанка
const idx = Math.max(0, Math.min(TOTAL_CHUNKS - 1, parseInt(chunkIndex, 10) || 0));
const start = idx * CHUNK_SIZE;
const end = Math.min(IMAGE_BUFFER.length, start + CHUNK_SIZE);
const slice = IMAGE_BUFFER.slice(start, end);


// Шифруем chunk
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
const ciphertext = Buffer.concat([cipher.update(slice), cipher.final()]);
const tag = cipher.getAuthTag();


res.json({
ciphertext: ciphertext.toString('base64'),
iv: iv.toString('base64'),
tag: tag.toString('base64'),
chunkIndex: idx,
totalChunks: TOTAL_CHUNKS
});
} catch (e) {
console.error(e);
res.status(500).json({error: String(e)});
}
});


app.listen(PORT, () => {
console.log(`Server listening on http://localhost:${PORT}`);
});