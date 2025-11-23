import { readFileSync } from 'fs';
import { join } from 'path';
import crypto from 'crypto';

const IMAGE_BUFFER = readFileSync(join(process.cwd(), 'image.png'));
const CHUNK_SIZE = 32 * 1024;
const TOTAL_CHUNKS = Math.ceil(IMAGE_BUFFER.length / CHUNK_SIZE);

const sessions = new Map();

function createServerKeypair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

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

export default async function handler(req, res) {
  if (req.method === 'GET' && req.query.route === 'session-init') {
    const sid = crypto.randomBytes(8).toString('hex');
    const ecdh = createServerKeypair();
    sessions.set(sid, ecdh);

    return res.json({
      sessionId: sid,
      serverPublic: ecdh.getPublicKey().toString('base64'),
      chunkSize: CHUNK_SIZE,
      totalChunks: TOTAL_CHUNKS
    });
  }

  if (req.method === 'POST' && req.query.route === 'get-chunk') {
    const { clientPublic, chunkIndex, sessionId } = req.body;
    if (!sessions.has(sessionId)) return res.status(400).json({ error: 'Invalid session' });

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

    return res.json({
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      chunkIndex: idx,
      totalChunks: TOTAL_CHUNKS
    });
  }

  return res.status(404).json({ error: 'Unknown route' });
}
