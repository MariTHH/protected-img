document.addEventListener('contextmenu', e => e.preventDefault());

const status = document.getElementById('status');
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');

function setStatus(t) { status.textContent = t }

async function main() {
  try {
    setStatus('Initializing session...');

    const sessRes = await fetch('/session-init').then(r => r.json());
    const chunkSize = sessRes.chunkSize;
    const totalChunks = sessRes.totalChunks;

    // ===== FIXED: PROPER HKDF IMPLEMENTATION =====
    const salt = new Uint8Array(16);
    const info = new TextEncoder().encode('protected-image');
    
    // FIX: Use proper HKDF derivation (matching server)
    const sharedSecret = new Uint8Array(32); // This should come from key exchange
    
    // Import key for HKDF
    const baseKey = await crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );
    
    // Derive AES key
    const aesKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        salt: salt,
        info: info,
        hash: 'SHA-256'
      },
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

      // FIX: Combine ciphertext and tag for Web Crypto API
      const combined = new Uint8Array(ct.length + tag.length);
      combined.set(ct, 0);
      combined.set(tag, ct.length);

      try {
        const plain = await crypto.subtle.decrypt(
          { 
            name: 'AES-GCM', 
            iv: iv,
            additionalData: undefined,
            tagLength: 128
          },
          aesKey,
          combined
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

      // Add protection
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
      
      document.addEventListener('copy', e => {
        e.preventDefault();
        e.clipboardData.setData('text/plain', 'Content protected');
      });
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

// Start the application
main();