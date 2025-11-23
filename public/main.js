document.addEventListener('contextmenu', e => e.preventDefault());

const status = document.getElementById('status');
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');

function setStatus(t) { status.textContent = t }

// HKDF implementation for client
async function hkdf(client, salt, info, length = 32) {
  const key = await crypto.subtle.importKey(
    'raw',
    client,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const prk = await crypto.subtle.sign('HMAC', key, salt);
  
  let output = new Uint8Array();
  let prev = new Uint8Array();
  let i = 0;
  
  while (output.length < length) {
    i += 1;
    const input = new Uint8Array([
      ...prev,
      ...info,
      i
    ]);
    
    const key2 = await crypto.subtle.importKey(
      'raw',
      prk,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const chunk = await crypto.subtle.sign('HMAC', key2, input);
    prev = new Uint8Array(chunk);
    output = new Uint8Array([...output, ...prev]);
  }
  
  return output.slice(0, length);
}

async function main() {
  try {
    setStatus('Initializing session...');

    const sessRes = await fetch('/session-init').then(r => r.json());
    const totalChunks = sessRes.totalChunks;
    
    // FIXED: Get the shared secret from server
    const sharedSecret = Uint8Array.from(atob(sessRes.sharedSecret), c => c.charCodeAt(0));

    // FIXED: Derive AES key using the same method as server
    const salt = new Uint8Array(16);
    const info = new TextEncoder().encode('protected-image');
    
    const derivedKey = await hkdf(sharedSecret, salt, info, 32);
    
    const aesKey = await crypto.subtle.importKey(
      'raw',
      derivedKey,
      { name: 'AES-GCM' },
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

      // Combine ciphertext + tag
      const encryptedData = new Uint8Array(ct.length + tag.length);
      encryptedData.set(ct, 0);
      encryptedData.set(tag, ct.length);

      try {
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          aesKey,
          encryptedData
        );
        chunks.push(new Uint8Array(plain));
      } catch (decryptError) {
        console.error(`Decryption failed for chunk ${i}:`, decryptError);
        throw decryptError;
      }
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
      blocker.style.cssText = `
        position: fixed;
        left: 0; top: 0;
        width: 100%; height: 100%;
        z-index: 9999;
        background: transparent;
        pointer-events: none;
      `;
      document.body.appendChild(blocker);
    };
    
    img.onerror = () => {
      setStatus('Error loading image');
    };
    
    img.src = url;

  } catch (error) {
    console.error('Fatal error:', error);
    setStatus(`Error: ${error.message}`);
  }
}

main();