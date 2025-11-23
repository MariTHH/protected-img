const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const IMAGE_PATH = path.join(__dirname, '..', 'image.png');
const CHUNK_SIZE = 32 * 1024;
const IMAGE_BUFFER = fs.readFileSync(IMAGE_PATH);
const TOTAL_CHUNKS = Math.ceil(IMAGE_BUFFER.length / CHUNK_SIZE);

const sessions = new Map();

function createServerKeypair() {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

module.exports = async (req, res) => {
  const sid = crypto.randomBytes(8).toString('hex');
  const ecdh = createServerKeypair();
  sessions.set(sid, ecdh);

  // Временно сохраняем session для get-chunk через глобальный объект
  global._sessions = sessions;

  res.json({
    sessionId: sid,
    serverPublic: ecdh.getPublicKey().toString('base64'),
    chunkSize: CHUNK_SIZE,
    totalChunks: TOTAL_CHUNKS
  });
};
