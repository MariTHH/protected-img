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

// SIMPLIFIED: Use a static AES key (32 bytes)
const STATIC_AES_KEY = Buffer.alloc(32, 0); // 32 zeros

// Pre-calculate all chunks
const chunks = [];
for (let i = 0; i < TOTAL_CHUNKS; i++) {
  const start = i * CHUNK_SIZE;
  const end = Math.min(IMAGE_BUFFER.length, start + CHUNK_SIZE);
  const slice = IMAGE_BUFFER.slice(start, end);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', STATIC_AES_KEY, iv);
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
    totalChunks: TOTAL_CHUNKS
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