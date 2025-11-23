const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ===== CONFIG =====
const IMAGE_PATH = path.join(__dirname, '..', 'image.png');
const CHUNK_SIZE = 32 * 1024;

if (!fs.existsSync(IMAGE_PATH)) {
  console.error('Put an image named image.png in project root');
  process.exit(1);
}

const IMAGE_BUFFER = fs.readFileSync(IMAGE_PATH);
const TOTAL_CHUNKS = Math.ceil(IMAGE_BUFFER.length / CHUNK_SIZE);

// ===== HKDF =====
function hkdf(keyMaterial, salt, info, length = 32) {
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

// ===== ONE-TIME SERVER KEY =====
const serverECDH = crypto.createECDH('prime256v1');
serverECDH.generateKeys();
const serverPublicB64 = serverECDH.getPublicKey().toString('base64');

// ===== PRE-CALCULATED CHUNKS =====
const salt = Buffer.alloc(16, 0);
const sharedSecret = crypto.randomBytes(32); // static "shared secret" for all clients
const aesKey = hkdf(sharedSecret, salt, Buffer.from('protected-image'));

const chunks = [];
for (let i = 0; i < TOTAL_CHUNKS; i++) {
  const start = i * CHUNK_SIZE;
  const end = Math.min(IMAGE_BUFFER.length, start + CHUNK_SIZE);
  const slice = IMAGE_BUFFER.slice(start, end);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(slice), cipher.final()]);
  const tag = cipher.getAuthTag();

  chunks.push({
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    chunkIndex: i
  });
}

// ===== VERCEL EXPORT =====
module.exports = (req, res) => {
  const url = req.url;

  if (url.startsWith('/session-init')) {
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({
      serverPublic: serverPublicB64,
      chunkSize: CHUNK_SIZE,
      totalChunks: TOTAL_CHUNKS
    }));
  }

  if (url.startsWith('/get-chunk') && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const { chunkIndex } = JSON.parse(body);
      const idx = Math.max(0, Math.min(TOTAL_CHUNKS - 1, Number(chunkIndex) || 0));
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ ...chunks[idx], totalChunks: TOTAL_CHUNKS }));
    });
    return;
  }

  res.statusCode = 404;
  res.end('Not Found');
};
