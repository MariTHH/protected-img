const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 8080;
const IMAGE_PATH = path.join(__dirname, 'image.png');
const CHUNK_SIZE = 32 * 1024;

if (!fs.existsSync(IMAGE_PATH)) {
  console.error('Put an image named image.png in project root');
  process.exit(1);
}

const IMAGE_BUFFER = fs.readFileSync(IMAGE_PATH);
const TOTAL_CHUNKS = Math.ceil(IMAGE_BUFFER.length / CHUNK_SIZE);

// FIXED: Use a STATIC shared secret that client can replicate
const SHARED_SECRET = new Uint8Array(32); // 32 bytes of zeros - CLIENT CAN USE THIS

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

// Pre-calculate AES key once
const salt = Buffer.alloc(16, 0);
const aesKey = hkdf(SHARED_SECRET, salt, Buffer.from('protected-image'), 32);

// Pre-calculate all chunks
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

// ROUTES
app.get('/session-init', (req, res) => {
  res.json({
    chunkSize: CHUNK_SIZE,
    totalChunks: TOTAL_CHUNKS,
    // Send the static shared secret to client (in real app, use proper key exchange)
    sharedSecret: Buffer.from(SHARED_SECRET).toString('base64')
  });
});

app.post('/get-chunk', (req, res) => {
  try {
    const { chunkIndex } = req.body;
    const idx = Math.max(0, Math.min(TOTAL_CHUNKS - 1, Number(chunkIndex) || 0));
    res.json({ ...chunks[idx], totalChunks: TOTAL_CHUNKS });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));