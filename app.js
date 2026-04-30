/**
 * NOTE CRYPT - Web Version
 * Fitur: Setup/Login toggle, Chunked Upload, Backup & Restore
 */

// ============================================================
// KONSTANTA
// ============================================================
const DB_NAME = 'NoteCryptV4';
const DB_VERSION = 1;
const STORE_NOTES = 'notes';
const STORE_ATTACHMENTS = 'attachments';
const STORE_CHUNKS = 'chunks';
const STORE_AUTH = 'auth';

const CHUNK_SIZE = 1024 * 1024; // 1MB per chunk

let currentPassphrase = null;
let currentNoteId = null;
let failedAttempts = 0;
let db = null;
let notesCache = [];
let attachmentsCache = new Map();

// ============================================================
// UTILITY
// ============================================================
function showLoading() { document.getElementById('loading-overlay').style.display = 'flex'; }
function hideLoading() { document.getElementById('loading-overlay').style.display = 'none'; }
function showScreen(screenId) {
    document.getElementById('auth-screen').style.display = 'none';
    document.getElementById('main-screen').style.display = 'none';
    document.getElementById(screenId).style.display = 'block';
}
function escapeHtml(text) { if (!text) return ''; const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }
function formatBytes(bytes) { if (bytes === 0) return '0 B'; const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]; }

// Toggle between Setup and Login forms
function showSetupForm() {
    document.getElementById('setup-form').style.display = 'block';
    document.getElementById('login-form').style.display = 'none';
    document.getElementById('toggle-auth-text').innerHTML = 'Sudah punya akun? <span class="toggle-link">Masuk</span>';
    document.getElementById('attempt-warning').style.display = 'none';
    document.getElementById('new-passphrase').value = '';
    document.getElementById('confirm-passphrase').value = '';
}

function showLoginForm() {
    document.getElementById('setup-form').style.display = 'none';
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('toggle-auth-text').innerHTML = 'Belum punya akun? <span class="toggle-link">Buat baru</span>';
    document.getElementById('attempt-warning').style.display = 'none';
    document.getElementById('passphrase-input').value = '';
}

// ============================================================
// KRIPTOGRAFI
// ============================================================
async function deriveKey(passphrase, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: 50000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptChunk(data, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data);
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    return { data: Array.from(combined) };
}

async function decryptChunk(encryptedObj, passphrase) {
    const combined = new Uint8Array(encryptedObj.data);
    const salt = combined.slice(0, 32);
    const iv = combined.slice(32, 44);
    const ciphertext = combined.slice(44);
    const key = await deriveKey(passphrase, salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
    return new Uint8Array(decrypted);
}

async function encryptNoteData(data, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(data));
    return { salt: Array.from(salt), iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
}

async function decryptNoteData(encryptedObj, passphrase) {
    const salt = new Uint8Array(encryptedObj.salt);
    const iv = new Uint8Array(encryptedObj.iv);
    const ciphertext = new Uint8Array(encryptedObj.data);
    const key = await deriveKey(passphrase, salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
}

async function hashPassphrase(passphrase, salt = null) {
    const encoder = new TextEncoder();
    const actualSalt = salt || crypto.getRandomValues(new Uint8Array(32));
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: actualSalt, iterations: 50000, hash: 'SHA-256' }, keyMaterial, 256);
    return { salt: actualSalt, hash: new Uint8Array(hash) };
}

// ============================================================
// INDEXEDDB
// ============================================================
async function initDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => { db = request.result; resolve(db); };
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(STORE_NOTES)) db.createObjectStore(STORE_NOTES, { keyPath: 'id' });
            if (!db.objectStoreNames.contains(STORE_ATTACHMENTS)) db.createObjectStore(STORE_ATTACHMENTS, { keyPath: 'id' });
            if (!db.objectStoreNames.contains(STORE_CHUNKS)) db.createObjectStore(STORE_CHUNKS, { keyPath: 'id' });
            if (!db.objectStoreNames.contains(STORE_AUTH)) db.createObjectStore(STORE_AUTH, { keyPath: 'key' });
        };
    });
}

async function getFromStore(storeName, key) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const req = tx.objectStore(storeName).get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

async function putToStore(storeName, data) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const req = tx.objectStore(storeName).put(data);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

async function deleteFromStore(storeName, key) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readwrite');
        const req = tx.objectStore(storeName).delete(key);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
    });
}

async function getAllFromStore(storeName) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction(storeName, 'readonly');
        const req = tx.objectStore(storeName).getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

// ============================================================
// AUTHENTIKASI
// ============================================================
async function checkAuth() { return (await getFromStore(STORE_AUTH, 'passphrase_hash')) !== undefined; }
async function registerPassphrase(passphrase) { const { salt, hash } = await hashPassphrase(passphrase); await putToStore(STORE_AUTH, { key: 'passphrase_hash', salt: Array.from(salt), hash: Array.from(hash), failedAttempts: 0 }); }
async function verifyPassphrase(passphrase) {
    const authData = await getFromStore(STORE_AUTH, 'passphrase_hash');
    if (!authData) return false;
    const salt = new Uint8Array(authData.salt);
    const storedHash = new Uint8Array(authData.hash);
    const { hash } = await hashPassphrase(passphrase, salt);
    if (hash.length === storedHash.length && hash.every((v, i) => v === storedHash[i])) {
        await putToStore(STORE_AUTH, { ...authData, failedAttempts: 0 });
        failedAttempts = 0;
        return true;
    }
    failedAttempts = (authData.failedAttempts || 0) + 1;
    await putToStore(STORE_AUTH, { ...authData, failedAttempts });
    return false;
}
async function getFailedAttempts() { const authData = await getFromStore(STORE_AUTH, 'passphrase_hash'); return authData?.failedAttempts || 0; }
async function wipeAllData() {
    const notes = await getAllFromStore(STORE_NOTES);
    for (const note of notes) await deleteFromStore(STORE_NOTES, note.id);
    const attachments = await getAllFromStore(STORE_ATTACHMENTS);
    for (const att of attachments) {
        for (let i = 0; i < att.totalChunks; i++) await deleteFromStore(STORE_CHUNKS, `${att.id}_chunk_${i}`);
        await deleteFromStore(STORE_ATTACHMENTS, att.id);
    }
    await deleteFromStore(STORE_AUTH, 'passphrase_hash');
    notesCache = [];
    attachmentsCache.clear();
}

// ============================================================
// BACKUP & RESTORE
// ============================================================
async function exportBackup() {
    showLoading();
    try {
        const notes = await getAllFromStore(STORE_NOTES);
        const attachments = await getAllFromStore(STORE_ATTACHMENTS);
        const chunks = await getAllFromStore(STORE_CHUNKS);
        const auth = await getFromStore(STORE_AUTH, 'passphrase_hash');
        
        const backupData = {
            version: 2,
            timestamp: new Date().toISOString(),
            app: 'NOTE_CRYPT',
            notes: notes,
            attachments: attachments,
            chunks: chunks,
            auth: auth
        };
        
        const jsonStr = JSON.stringify(backupData, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `note_crypt_backup_${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.json`;
        a.click();
        URL.revokeObjectURL(url);
        alert('✅ Backup berhasil dibuat!\nFile JSON telah diunduh.\nSimpan file ini di tempat aman.');
    } catch(err) {
        alert('Gagal backup: ' + err.message);
    } finally {
        hideLoading();
    }
}

async function importBackup() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'application/json';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = async (event) => {
            try {
                const backupData = JSON.parse(event.target.result);
                
                if (backupData.app !== 'NOTE_CRYPT' && backupData.version !== 2) {
                    if (!confirm('File ini mungkin bukan backup NOTE CRYPT. Lanjutkan?')) return;
                }
                
                if (!confirm('⚠️ PERINGATAN ⚠️\n\nRestore akan MENIMPA semua data yang ada saat ini!\nData lama akan hilang.\n\nLanjutkan restore?')) return;
                
                showLoading();
                
                // Hapus data lama
                await wipeAllData();
                
                // Restore data
                for (const note of backupData.notes || []) {
                    await putToStore(STORE_NOTES, note);
                }
                for (const att of backupData.attachments || []) {
                    await putToStore(STORE_ATTACHMENTS, att);
                }
                for (const chunk of backupData.chunks || []) {
                    await putToStore(STORE_CHUNKS, chunk);
                }
                if (backupData.auth) {
                    await putToStore(STORE_AUTH, backupData.auth);
                }
                
                await refreshCache();
                alert('✅ Restore berhasil!\nSilakan login ulang dengan passphrase lama Anda.');
                location.reload();
                
            } catch(err) {
                alert('❌ File backup rusak atau tidak valid: ' + err.message);
            } finally {
                hideLoading();
            }
        };
        reader.readAsText(file);
    };
    input.click();
}

// ============================================================
// GAMBAR (CHUNKED UPLOAD)
// ============================================================
async function saveLargeImage(file) {
    return new Promise(async (resolve, reject) => {
        const attachmentId = crypto.randomUUID();
        const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
        if (totalChunks > 500) { reject(new Error('File terlalu besar (maks 500MB)')); return; }
        showLoading();
        try {
            for (let i = 0; i < totalChunks; i++) {
                const start = i * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunkBlob = file.slice(start, end);
                const chunkBuffer = await chunkBlob.arrayBuffer();
                const encrypted = await encryptChunk(new Uint8Array(chunkBuffer), currentPassphrase);
                await putToStore(STORE_CHUNKS, { id: `${attachmentId}_chunk_${i}`, attachmentId, chunkIndex: i, totalChunks, data: encrypted.data });
                const percent = Math.round((i + 1) / totalChunks * 100);
                document.getElementById('storage-info').innerHTML = `📤 Upload: ${percent}%`;
            }
            await putToStore(STORE_ATTACHMENTS, { id: attachmentId, type: 'chunked', originalName: file.name, mimeType: file.type, totalChunks, fileSize: file.size });
            hideLoading();
            resolve({ id: attachmentId, originalName: file.name, size: file.size });
        } catch (err) { hideLoading(); reject(err); }
    });
}

async function loadLargeImage(attachmentId) {
    const meta = await getFromStore(STORE_ATTACHMENTS, attachmentId);
    if (!meta || meta.type !== 'chunked') return null;
    const chunks = [];
    for (let i = 0; i < meta.totalChunks; i++) {
        const chunkData = await getFromStore(STORE_CHUNKS, `${attachmentId}_chunk_${i}`);
        if (!chunkData) return null;
        const decrypted = await decryptChunk({ data: chunkData.data }, currentPassphrase);
        chunks.push(decrypted);
    }
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const fullImage = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) { fullImage.set(chunk, offset); offset += chunk.length; }
    return { blob: new Blob([fullImage], { type: meta.mimeType }), originalName: meta.originalName };
}

async function deleteLargeImage(attachmentId) {
    const meta = await getFromStore(STORE_ATTACHMENTS, attachmentId);
    if (meta && meta.type === 'chunked') {
        for (let i = 0; i < meta.totalChunks; i++) await deleteFromStore(STORE_CHUNKS, `${attachmentId}_chunk_${i}`);
    }
    await deleteFromStore(STORE_ATTACHMENTS, attachmentId);
    attachmentsCache.delete(attachmentId);
}

// ============================================================
// CATATAN
// ============================================================
async function saveNote(noteId, title, content, attachments) {
    const encrypted = await encryptNoteData(JSON.stringify({ title, content, attachments: attachments || [], updated: new Date().toISOString() }), currentPassphrase);
    await putToStore(STORE_NOTES, { id: noteId, encrypted, updated: new Date().toISOString() });
    await refreshCache();
}
async function loadNote(noteId) {
    const note = await getFromStore(STORE_NOTES, noteId);
    if (!note) return null;
    try { const decrypted = await decryptNoteData(note.encrypted, currentPassphrase); return JSON.parse(decrypted); }
    catch(e) { return null; }
}
async function refreshCache() {
    const notes = await getAllFromStore(STORE_NOTES);
    notesCache = [];
    for (const note of notes) {
        try { const decrypted = await decryptNoteData(note.encrypted, currentPassphrase); const data = JSON.parse(decrypted); notesCache.push({ id: note.id, title: data.title || 'Untitled', updated: note.updated, attachments: data.attachments || [] }); }
        catch(e) { notesCache.push({ id: note.id, title: '[Error]', updated: note.updated, attachments: [] }); }
    }
    notesCache.sort((a, b) => new Date(b.updated) - new Date(a.updated));
}
async function deleteNote(noteId) {
    const note = notesCache.find(n => n.id === noteId);
    if (note?.attachments) for (const att of note.attachments) await deleteLargeImage(att.id);
    await deleteFromStore(STORE_NOTES, noteId);
    await refreshCache();
}

// ============================================================
// RENDER FUNCTIONS
// ============================================================
function renderNotes() {
    const container = document.getElementById('notes-list');
    if (notesCache.length === 0) { container.innerHTML = '<div class="empty-state">Belum ada catatan<br>Klik + untuk membuat</div>'; return; }
    let html = '';
    for (const note of notesCache) {
        const active = currentNoteId === note.id ? 'active' : '';
        html += `<div class="note-item ${active}" data-id="${note.id}"><div class="note-item-title">${escapeHtml(note.title.substring(0, 40))}</div><div class="note-item-date">${new Date(note.updated).toLocaleString()}</div></div>`;
    }
    container.innerHTML = html;
    document.querySelectorAll('.note-item').forEach(el => { el.addEventListener('click', () => onNoteClick(el.dataset.id)); });
}

async function renderAttachments() {
    const container = document.getElementById('attachment-list');
    const currentNote = notesCache.find(n => n.id === currentNoteId);
    const attachments = currentNote?.attachments || [];
    if (attachments.length === 0) { container.innerHTML = '<div class="empty-attachment">Belum ada gambar</div>'; return; }
    let html = '';
    for (const att of attachments) {
        html += `<div class="attachment-item" data-id="${att.id}"><div class="attachment-thumb" style="background:#1A1A1A;display:flex;align-items:center;justify-content:center;height:80px;">📷 ${formatBytes(att.size)}</div><div class="attachment-info">${escapeHtml(att.originalName.substring(0, 12))}</div><button class="attachment-delete" data-id="${att.id}">✕ Hapus</button></div>`;
    }
    container.innerHTML = html;
    document.querySelectorAll('.attachment-item').forEach(el => { el.addEventListener('click', (e) => { if (!e.target.classList.contains('attachment-delete')) onViewImage(el.dataset.id); }); });
    document.querySelectorAll('.attachment-delete').forEach(btn => { btn.addEventListener('click', (e) => { e.stopPropagation(); onDeleteAttachment(btn.dataset.id); }); });
}

// ============================================================
// EVENT HANDLERS
// ============================================================
async function onNoteClick(noteId) {
    showLoading();
    try {
        const data = await loadNote(noteId);
        if (data) { currentNoteId = noteId; document.getElementById('note-title').value = data.title || ''; document.getElementById('note-content').value = data.content || ''; await renderAttachments(); renderNotes(); }
    } catch(e) { alert('Error: ' + e.message); } finally { hideLoading(); }
}
async function onNewNote() { currentNoteId = null; document.getElementById('note-title').value = ''; document.getElementById('note-content').value = ''; document.getElementById('attachment-list').innerHTML = '<div class="empty-attachment">Belum ada gambar</div>'; renderNotes(); }
async function onSaveNote() {
    const title = document.getElementById('note-title').value.trim();
    const content = document.getElementById('note-content').value;
    if (!title && !content) { alert('Isi judul atau konten catatan'); return; }
    showLoading();
    try {
        let attachments = [];
        if (currentNoteId) { const existing = await loadNote(currentNoteId); if (existing) attachments = existing.attachments || []; }
        if (!currentNoteId) currentNoteId = crypto.randomUUID();
        await saveNote(currentNoteId, title || 'Untitled', content, attachments);
        renderNotes();
        alert('Catatan tersimpan');
    } catch(e) { alert('Gagal menyimpan: ' + e.message); } finally { hideLoading(); }
}
async function onDeleteNote() {
    if (!currentNoteId) { alert('Pilih catatan terlebih dahulu'); return; }
    if (!confirm('Yakin ingin menghapus catatan ini beserta semua gambarnya?')) return;
    showLoading();
    try {
        await deleteNote(currentNoteId);
        currentNoteId = null;
        document.getElementById('note-title').value = '';
        document.getElementById('note-content').value = '';
        document.getElementById('attachment-list').innerHTML = '<div class="empty-attachment">Belum ada gambar</div>';
        renderNotes();
        alert('Catatan dihapus');
    } catch(e) { alert('Gagal menghapus: ' + e.message); } finally { hideLoading(); }
}
async function onAddImage() {
    if (!currentNoteId) { alert('Buat atau pilih catatan terlebih dahulu'); return; }
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const sizeMB = file.size / (1024 * 1024);
        if (!confirm(`Upload gambar: ${file.name} (${sizeMB.toFixed(1)}MB)\n\nGambar akan dipecah jadi potongan 1MB. Lanjutkan?`)) return;
        try {
            const result = await saveLargeImage(file);
            const noteData = await loadNote(currentNoteId);
            const attachments = noteData?.attachments || [];
            attachments.push({ id: result.id, originalName: result.originalName, size: result.size });
            await saveNote(currentNoteId, noteData?.title || '', noteData?.content || '', attachments);
            await renderAttachments();
            alert(`✅ Gambar ${result.originalName} berhasil diupload (${formatBytes(result.size)})`);
        } catch(err) { alert('Gagal upload: ' + err.message); }
    };
    input.click();
}
async function onViewImage(attachmentId) {
    showLoading();
    try {
        const result = await loadLargeImage(attachmentId);
        if (result) {
            const url = URL.createObjectURL(result.blob);
            const modal = document.getElementById('image-modal');
            document.getElementById('modal-image').src = url;
            document.getElementById('modal-info').textContent = `${result.originalName} | ${formatBytes(result.blob.size)}`;
            modal.style.display = 'flex';
            document.getElementById('modal-save').onclick = () => { const a = document.createElement('a'); a.href = url; a.download = result.originalName; a.click(); };
        } else { alert('Gambar tidak ditemukan'); }
    } catch(e) { alert('Error: ' + e.message); } finally { hideLoading(); }
}
async function onDeleteAttachment(attachmentId) {
    if (!confirm('Hapus gambar ini?')) return;
    showLoading();
    try {
        const noteData = await loadNote(currentNoteId);
        if (noteData) {
            noteData.attachments = noteData.attachments.filter(a => a.id !== attachmentId);
            await saveNote(currentNoteId, noteData.title, noteData.content, noteData.attachments);
            await deleteLargeImage(attachmentId);
            await renderAttachments();
        }
    } catch(e) { alert('Gagal hapus: ' + e.message); } finally { hideLoading(); }
}

// ============================================================
// AUTH HANDLERS
// ============================================================
async function onLogin() {
    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase) { alert('Masukkan passphrase'); return; }
    showLoading();
    try {
        const valid = await verifyPassphrase(passphrase);
        if (valid) {
            currentPassphrase = passphrase;
            await refreshCache();
            showScreen('main-screen');
            document.getElementById('mode-badge').textContent = '🔐 SECURE VAULT';
            renderNotes();
            currentNoteId = null;
            document.getElementById('note-title').value = '';
            document.getElementById('note-content').value = '';
            document.getElementById('attachment-list').innerHTML = '<div class="empty-attachment">Belum ada gambar</div>';
            document.getElementById('storage-info').innerHTML = `📊 ${notesCache.length} catatan | Gunakan 💾 untuk backup`;
        } else {
            const attempts = await getFailedAttempts();
            if (attempts >= 3) { if (confirm('3x percobaan gagal! Hapus semua data?')) { await wipeAllData(); location.reload(); } }
            else { const warn = document.getElementById('attempt-warning'); warn.textContent = `⚠️ Passphrase salah! Sisa percobaan: ${3 - attempts}/3`; warn.style.display = 'block'; document.getElementById('passphrase-input').value = ''; }
        }
    } catch(e) { alert('Error: ' + e.message); } finally { hideLoading(); }
}

async function onSetup() {
    const p1 = document.getElementById('new-passphrase').value;
    const p2 = document.getElementById('confirm-passphrase').value;
    if (p1.length < 8) { alert('Passphrase minimal 8 karakter'); return; }
    if (p1 !== p2) { alert('Passphrase tidak cocok'); return; }
    showLoading();
    try {
        await registerPassphrase(p1);
        alert('✅ Vault berhasil dibuat! Silakan login dengan passphrase Anda.');
        showLoginForm();
        document.getElementById('new-passphrase').value = '';
        document.getElementById('confirm-passphrase').value = '';
    } catch(e) { alert('Error: ' + e.message); } finally { hideLoading(); }
}

async function onDecoyMode() {
    currentPassphrase = 'decoy_mode_' + Date.now();
    notesCache = [];
    showScreen('main-screen');
    document.getElementById('mode-badge').textContent = '📦 DECOY MODE (Data Tidak Terenkripsi)';
    renderNotes();
    currentNoteId = null;
    document.getElementById('note-title').value = '';
    document.getElementById('note-content').value = '';
    document.getElementById('attachment-list').innerHTML = '<div class="empty-attachment">Belum ada gambar</div>';
    document.getElementById('storage-info').innerHTML = '⚠️ DECOY MODE - Data tidak aman';
}

async function onWipe() { 
    if (!confirm('⚠️ PERINGATAN AKHIR ⚠️\n\nSEMUA CATATAN DAN GAMBAR AKAN DIHAPUS PERMANEN\nTIDAK BISA DIKEMBALIKAN\n\nApakah Anda yakin?')) return; 
    if (prompt('Ketik "HAPUS" untuk konfirmasi') !== 'HAPUS') return; 
    showLoading(); 
    try { 
        await wipeAllData(); 
        alert('✅ Semua data telah dihapus. Halaman akan refresh.');
        location.reload(); 
    } catch(e) { alert('Error: ' + e.message); } 
    finally { hideLoading(); } 
}

async function onLogout() { 
    currentPassphrase = null; 
    currentNoteId = null; 
    notesCache = []; 
    showScreen('auth-screen'); 
    showLoginForm();
    document.getElementById('passphrase-input').value = ''; 
    document.getElementById('attempt-warning').style.display = 'none'; 
}

// ============================================================
// INIT
// ============================================================
async function init() {
    await initDB();
    const hasAuth = await checkAuth();
    
    showScreen('auth-screen');
    
    if (hasAuth) {
        showLoginForm();
    } else {
        showSetupForm();
    }
    
    // Bind event handlers
    document.getElementById('login-btn').onclick = onLogin;
    document.getElementById('setup-create-btn').onclick = onSetup;
    document.getElementById('decoy-btn').onclick = onDecoyMode;
    document.getElementById('wipe-btn').onclick = onWipe;
    document.getElementById('new-note-btn').onclick = onNewNote;
    document.getElementById('logout-btn').onclick = onLogout;
    document.getElementById('wipe-main-btn').onclick = onWipe;
    document.getElementById('save-note-btn').onclick = onSaveNote;
    document.getElementById('delete-note-btn').onclick = onDeleteNote;
    document.getElementById('add-image-btn').onclick = onAddImage;
    document.getElementById('backup-btn').onclick = exportBackup;
    document.getElementById('restore-btn').onclick = importBackup;
    document.getElementById('modal-close').onclick = () => document.getElementById('image-modal').style.display = 'none';
    document.getElementById('image-modal').onclick = (e) => { if (e.target.id === 'image-modal') document.getElementById('image-modal').style.display = 'none'; };
    
    // Toggle link handler
    document.getElementById('toggle-auth-text').addEventListener('click', (e) => {
        if (e.target.classList.contains('toggle-link')) {
            const isLoginVisible = document.getElementById('login-form').style.display !== 'none';
            if (isLoginVisible) {
                showSetupForm();
            } else {
                showLoginForm();
            }
        }
    });
    
    // Enter key handlers
    document.getElementById('passphrase-input').addEventListener('keypress', (e) => { if (e.key === 'Enter') onLogin(); });
    document.getElementById('new-passphrase').addEventListener('keypress', (e) => { if (e.key === 'Enter') onSetup(); });
    document.getElementById('confirm-passphrase').addEventListener('keypress', (e) => { if (e.key === 'Enter') onSetup(); });
}

init();