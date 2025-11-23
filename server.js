const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// === SETTINGS ===
const IMAGE_PATH = path.join(process.cwd(), 'image.png');
const CHUNK_SIZE = 32 * 1024; // 32 KB per chunk

// read image
if (!fs.existsSync(IMAGE_PATH)) {
  console.error('image.png missing in project root');
}

const IMAGE_BUFFER = fs.readFileSync(IMAGE_PATH);
const TOTAL_CHUNKS = Math.ceil(IMAGE_BUFFER.length / CHUNK_SIZE);

// === HKDF helper ===
function hkdf(keyMaterial, salt, info, length = 32) {
  const prk = crypto.createHmac('sha256', salt).update(keyMaterial).digest();
  let prev = Buffer.alloc(0);
  const output = [];
  let i = 0;
  while (Buffer.concat(output).length < length) {
    i++;
    const hmac = crypto.createHmac('sha256', prk);
    hmac.update(prev);
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    prev = hmac.digest();
    output.push(prev);
  }
  return Buffer.concat(output).slice(0, length);
}

// === session store ===
const sessions = new Map();

function createServerKeypair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

module.exports = async (req, res) => {
  // === CORS FIX FOR VERCEL ===
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // route: /api/server.js?route=session-init
  const route = req.query.route;

  // -------------------------
  //     SESSION INIT
  // -------------------------
  if (route === 'session-init') {
    const sid = crypto.randomBytes(8).toString('hex');
    const ecdh = createServerKeypair();
    sessions.set(sid, ecdh);

    res.setHeader('Cache-Control', 'no-store');

    return res.json({
      sessionId: sid,
      serverPublic: ecdh.getPublicKey().toString('base64'),
      chunkSize: CHUNK_SIZE,
      totalChunks: TOTAL_CHUNKS
    });
  }

  // -------------------------
  //        GET CHUNK
  // -------------------------
  if (route === 'get-chunk') {
    try {
      const { clientPublic, chunkIndex, sessionId } = req.body;

      if (!sessions.has(sessionId)) {
        return res.status(400).json({ error: 'Invalid or expired session' });
      }

      const serverECDH = sessions.get(sessionId);
      const clientPubBuf = Buffer.from(clientPublic, 'base64');

      const sharedSecret = serverECDH.computeSecret(clientPubBuf);

      // derive AES key
      const salt = Buffer.alloc(16, 0);
      sharedSecret.copy(salt, 0, 0, Math.min(16, sharedSecret.length));

      const aesKey = hkdf(sharedSecret, salt, Buffer.from('protected-image'), 32);

      const idx = Math.max(0, Math.min(TOTAL_CHUNKS - 1, parseInt(chunkIndex) || 0));
      const start = idx * CHUNK_SIZE;
      const end = Math.min(IMAGE_BUFFER.length, start + CHUNK_SIZE);

      const slice = IMAGE_BUFFER.slice(start, end);

      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

      const ciphertext = Buffer.concat([cipher.update(slice), cipher.final()]);
      const tag = cipher.getAuthTag();

      return res.json({
        ciphertext: ciphertext.toString('base64'),
        iv: iv.toString('base64'),
        tag: tag.toString('base64'),
        chunkIndex: idx,
        totalChunks: TOTAL_CHUNKS
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: String(e) });
    }
  }

  // unknown route
  res.status(404).json({ error: 'Not found' });
};
