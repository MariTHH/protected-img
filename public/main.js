// public/main.js
(async function(){
  // Блокируем ПКМ
  document.addEventListener('contextmenu', e => e.preventDefault());

  const status = document.getElementById('status');
  const canvas = document.getElementById('canvas');
  const ctx = canvas.getContext('2d');

  function setStatus(t){ status.textContent = t }

  setStatus('Initializing session...');

  // 1) Получаем публичный ключ сервера и параметры
  const sessRes = await fetch('/session-init').then(r => r.json());
  const serverPubB64 = sessRes.serverPublic;
  const chunkSize = sessRes.chunkSize;
  const totalChunks = sessRes.totalChunks;

  setStatus('Generating client ECDH key...');

  // 2) Генерируем ECDH ключ (P-256)
  const clientKey = await window.crypto.subtle.generateKey(
    {name: 'ECDH', namedCurve: 'P-256'},
    true,
    ['deriveBits']
  );

  const clientPubRaw = await window.crypto.subtle.exportKey('raw', clientKey.publicKey);
  const clientPubB64 = btoa(String.fromCharCode(...new Uint8Array(clientPubRaw)));

  // Вспомог: импорт публичного ключа сервера
  const serverPubRaw = Uint8Array.from(atob(serverPubB64), c=>c.charCodeAt(0)).buffer;
  const serverPublicKey = await window.crypto.subtle.importKey(
    'raw', serverPubRaw,
    {name: 'ECDH', namedCurve: 'P-256'},
    true, []
  );

  // Функция: derive symmetric key (AES-GCM 256) из ECDH
  async function deriveAesKey() {
    const sharedBits = await window.crypto.subtle.deriveBits(
      {name: 'ECDH', public: serverPublicKey},
      clientKey.privateKey,
      256
    );
    // HKDF-like: используем subtle.importKey + deriveKey with HKDF
    const salt = new Uint8Array(16);
    const info = new TextEncoder().encode('protected-image');
    const baseKey = await window.crypto.subtle.importKey('raw', sharedBits, {name:'HKDF'}, false, ['deriveKey']);
    const aesKey = await window.crypto.subtle.deriveKey(
      {name:'HKDF', hash:'SHA-256', salt, info},
      baseKey,
      {name:'AES-GCM', length:256},
      false,
      ['decrypt']
    );
    return aesKey;
  }

  setStatus('Deriving keys...');
  const aesKey = await deriveAesKey();

  // Fetch and assemble chunks
  const chunks = [];
  setStatus('Downloading chunks...');

  for (let i = 0; i < totalChunks; i++){
    setStatus(`Downloading chunk ${i+1}/${totalChunks}...`);
    // Запрашиваем у сервера зашифрованный чанк
    const resp = await fetch('/get-chunk', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ clientPublic: clientPubB64, chunkIndex: i })
    }).then(r=>r.json());

    if (resp.error) throw new Error(resp.error);

    const ct = Uint8Array.from(atob(resp.ciphertext), c=>c.charCodeAt(0));
    const iv = Uint8Array.from(atob(resp.iv), c=>c.charCodeAt(0));
    const tag = Uint8Array.from(atob(resp.tag), c=>c.charCodeAt(0));
    // Node combined ciphertext already without tag; tag is separate. WebCrypto expects ciphertext+tag concatenated.
    const full = new Uint8Array(ct.length + tag.length);
    full.set(ct, 0); full.set(tag, ct.length);

    // Расшифровываем
    const plain = await window.crypto.subtle.decrypt(
      {name:'AES-GCM', iv: iv, tagLength: 128},
      aesKey,
      full.buffer
    );

    chunks.push(new Uint8Array(plain));
  }

  setStatus('Assembling image...');
  // Собираем все чанки в один ArrayBuffer
  const totalBytes = chunks.reduce((s,c)=>s+c.length,0);
  const out = new Uint8Array(totalBytes);
  let ptr = 0;
  for (const c of chunks){ out.set(c, ptr); ptr += c.length }

  const blob = new Blob([out], {type: 'image/png'});
  const url = URL.createObjectURL(blob);

  // Рисуем в canvas
  const img = new Image();
  img.onload = () => {
    canvas.width = img.width;
    canvas.height = img.height;
    ctx.drawImage(img, 0, 0);
    URL.revokeObjectURL(url);
    setStatus('Loaded');

    // Перекрытие прозрачным блокером, чтобы затруднить drag
    const blocker = document.createElement('div');
    blocker.style.position = 'fixed'; blocker.style.left='0'; blocker.style.top='0';
    blocker.style.width = '100%'; blocker.style.height = '100%'; blocker.style.zIndex='9999';
    blocker.style.background = 'transparent';
    // Не даём pointer-events = none — хотим блокировать drag/select
    document.body.appendChild(blocker);

    // Дополнительно: очищаем clipboard/copy handlers
    document.addEventListener('copy', e => e.preventDefault());
  };
  img.src = url;

})();
