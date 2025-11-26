document.addEventListener('contextmenu', e => e.preventDefault());

const status = document.getElementById('status');
const canvas = document.getElementById('canvas');
const ctx = canvas.getContext('2d');

function setStatus(t) { status.textContent = t }

async function main() {
  try {
    setStatus('Initializing session...');

    const sessRes = await fetch('/session-init').then(r => r.json());
    const totalChunks = sessRes.totalChunks;

    const STATIC_AES_KEY = new Uint8Array(32); 
    
    const aesKey = await crypto.subtle.importKey(
      'raw',
      STATIC_AES_KEY,
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

      const encryptedData = new Uint8Array(ct.length + 16);
      encryptedData.set(ct, 0);
      encryptedData.set(tag, ct.length);

      try {
        const plain = await crypto.subtle.decrypt(
          { 
            name: 'AES-GCM', 
            iv: iv
          },
          aesKey,
          encryptedData
        );
        chunks.push(new Uint8Array(plain));
      } catch (decryptError) {
        console.error(`Decryption failed for chunk ${i}:`, decryptError);
        
        console.log('IV (hex):', Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('Tag (hex):', Array.from(tag).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('First 16 bytes CT (hex):', Array.from(ct.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(''));
        
        throw decryptError;
      }
    }

    setStatus('Assembling image...');
    const totalBytes = chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(totalBytes);
    let ptr = 0;
    for (const c of chunks) { 
      out.set(c, ptr); 
      ptr += c.length; 
    }

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
    
    img.onerror = (e) => {
      console.error('Image loading error:', e);
      setStatus('Error: Invalid image data');
    };
    
    img.src = url;

  } catch (error) {
    console.error('Fatal error:', error);
    setStatus(`Error: ${error.message}`);
  }
}

main();