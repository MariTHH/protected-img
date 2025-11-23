(async function () {
  document.addEventListener('contextmenu', e => e.preventDefault());

  const status = document.getElementById('status');
  const canvas = document.getElementById('canvas');
  const ctx = canvas.getContext('2d');

  function setStatus(t) { status.textContent = t }

  setStatus('Initializing session...');

  const sessRes = await fetch('/session-init').then(r => r.json());
  const chunkSize = sessRes.chunkSize;
  const totalChunks = sessRes.totalChunks;

  // ===== DERIVE AES KEY =====
  const salt = new Uint8Array(16);
  const info = new TextEncoder().encode('protected-image');
  const sharedSecret = crypto.getRandomValues(new Uint8Array(32)); // must match server static key
  const baseKey = await window.crypto.subtle.importKey(
    'raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']
  );
  const aesKey = await window.crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const chunks = [];
  setStatus('Downloading chunks...');

  for (let i = 0; i < totalChunks; i++) {
    setStatus(`Downloading chunk ${i + 1}/${totalChunks}...`);
    const resp = await fetch('/get-chunk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chunkIndex: i })
    }).then(r => r.json());

    const ct = Uint8Array.from(atob(resp.ciphertext), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(resp.iv), c => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(resp.tag), c => c.charCodeAt(0));

    const full = new Uint8Array(ct.length + tag.length);
    full.set(ct, 0); full.set(tag, ct.length);

    const plain = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      aesKey,
      full.buffer
    );
    chunks.push(new Uint8Array(plain));
  }

  setStatus('Assembling image...');
  const totalBytes = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(totalBytes);
  let ptr = 0;
  for (const c of chunks) { out.set(c, ptr); ptr += c.length; }

  const blob = new Blob([out], { type: 'image/png' });
  const url = URL.createObjectURL(blob);

  const img = new Image();
  img.onload = () => {
    canvas.width = img.width;
    canvas.height = img.height;
    ctx.drawImage(img, 0, 0);
    URL.revokeObjectURL(url);
    setStatus('Loaded');

    const blocker = document.createElement('div');
    blocker.style.position = 'fixed';
    blocker.style.left = '0';
    blocker.style.top = '0';
    blocker.style.width = '100%';
    blocker.style.height = '100%';
    blocker.style.zIndex = '9999';
    blocker.style.background = 'transparent';
    document.body.appendChild(blocker);
    document.addEventListener('copy', e => e.preventDefault());
  };
  img.src = url;

})();
