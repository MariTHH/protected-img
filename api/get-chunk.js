const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const IMAGE_PATH = path.join(__dirname, '..', 'image.png');
const CHUNK_SIZE = 32 * 1024;
const IMAGE_BUFFER = fs.readFileSync(IMAGE_PATH);
const TOTAL_CHUNKS = Math.ceil(IMAGE_BUFFER.length / CHUNK_SIZE);

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

module.exports = async (req, res) => {
  try {
    const { clientPublic, chunkIndex, sessionId } = req.body;
    const sessions = global._sessions;

    if (!sessions || !sessions.has(sessionId)) return res.status(400).json({ error: 'Invalid session' });

    const serverECDH = sessions.get(sessionId);
    const clientPubBuf = Buffer.from(clientPublic, 'base64');
    const sharedSecret = serverECDH.computeSecret(clientPubBuf);

    const salt = Buffer.alloc(16, 0);
    sharedSecret.copy(salt, 0, 0, Math.min(16, sharedSecret.length));
    const aesKey = hkdf(sharedSecret, salt, Buffer.from('protected-image'));

    const idx = Math.min(TOTAL_CHUNKS - 1, Math.max(0, Number(chunkIndex)));
    const slice = IMAGE_BUFFER.slice(idx * CHUNK_SIZE, (idx + 1) * CHUNK_SIZE);

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
    res.status(500).json({ error: String(e) });
  }
};
