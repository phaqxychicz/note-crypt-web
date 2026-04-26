/**
 * NOTE CRYPT - Web Version
 * AES-256-GCM Encryption | Client-side only
 * Data stored in IndexedDB
 */

// ============================================================
// CONSTANTS & GLOBALS
// ============================================================
const DB_NAME = 'NoteCryptDB';
const DB_VERSION = 2;
const STORE_NOTES = 'notes';
const STORE_ATTACHMENTS = 'attachments';
const STORE_AUTH = 'auth';

let currentPassphrase = null;
let currentDecoyMode = false;
let currentNoteId = null;
let failedAttempts = 0;
let db = null;

// DOM Elements
let currentView = 'login';

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
function showLoading() {
    document.getElementById('loading-overlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loading-overlay').style.display = 'none';
}

function showScreen(screenId) {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('setup-screen').style.display = 'none';
    document.getElementById('main-screen').style.display = 'none';
    document.getElementById(screenId).style.display = 'block';
    currentView = screenId;
}

function formatDate() {
    const now = new Date();
    return `${now.getDate()}/${now.getMonth() + 1}/${now.getFullYear()} ${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
}

// ============================================================
// CRYPTOGRAPHY FUNCTIONS (Web Crypto API)
// ============================================================
async function deriveKey(passphrase, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 200000,
            hash: 'SHA-256'
        },
        keyMaterial,
        {
            name: 'AES-GCM',
            length: 256
        },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(data, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    
    const encoder = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encoder.encode(data)
    );
    
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    
    return btoa(String.fromCharCode.apply(null, combined));
}

async function decryptData(encryptedBase64, passphrase) {
    const combined = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));
    const salt = combined.slice(0, 32);
    const iv = combined.slice(32, 44);
    const ciphertext = combined.slice(44);
    
    const key = await deriveKey(passphrase, salt);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
}

async function hashPassphrase(passphrase, salt = null) {
    const encoder = new TextEncoder();
    const actualSalt = salt || crypto.getRandomValues(new Uint8Array(32));
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(passphrase),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    
    const hash = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: actualSalt,
            iterations: 200000,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );
    
    if (salt) {
        return { salt: actualSalt, hash: new Uint8Array(hash) };
    }
    return { salt: actualSalt, hash: new Uint8Array(hash) };
}

// ============================================================
// INDEXEDDB OPERATIONS
// ============================================================
async function initDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            db = request.result;
            resolve(db);
        };
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            
            if (!db.objectStoreNames.contains(STORE_NOTES)) {
                db.createObjectStore(STORE_NOTES, { keyPath: 'id' });
            }
            if (!db.objectStoreNames.contains(STORE_ATTACHMENTS)) {
                db.createObjectStore(STORE_ATTACHMENTS, { keyPath: 'id' });
            }
            if (!db.objectStoreNames.contains(STORE_AUTH)) {
                db.createObjectStore(STORE_AUTH, { keyPath: 'key' });
            }
        };
    });
}

async function getFromStore(storeName, key) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, 'readonly');
        const store = transaction.objectStore(storeName);
        const request = store.get(key);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function putToStore(storeName, data) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.put(data);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

async function deleteFromStore(storeName, key) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.delete(key);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

async function getAllFromStore(storeName) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, 'readonly');
        const store = transaction.objectStore(storeName);
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

// ============================================================
// AUTH FUNCTIONS
// ============================================================
async function checkAuth() {
    const authData = await getFromStore(STORE_AUTH, 'passphrase_hash');
    return authData !== undefined;
}

async function registerPassphrase(passphrase) {
    const { salt, hash } = await hashPassphrase(passphrase);
    await putToStore(STORE_AUTH, {
        key: 'passphrase_hash',
        salt: Array.from(salt),
        hash: Array.from(hash),
        failedAttempts: 0
    });
    await putToStore(STORE_AUTH, {
        key: 'settings',
        decoyMode: false
    });
}

async function verifyPassphrase(passphrase) {
    const authData = await getFromStore(STORE_AUTH, 'passphrase_hash');
    if (!authData) return false;
    
    const salt = new Uint8Array(authData.salt);
    const storedHash = new Uint8Array(authData.hash);
    const { hash } = await hashPassphrase(passphrase, salt);
    
    if (hash.length === storedHash.length && hash.every((v, i) => v === storedHash[i])) {
        await putToStore(STORE_AUTH, { key: 'passphrase_hash', ...authData, failedAttempts: 0 });
        failedAttempts = 0;
        return true;
    }
    
    failedAttempts = (authData.failedAttempts || 0) + 1;
    await putToStore(STORE_AUTH, { key: 'passphrase_hash', ...authData, failedAttempts });
    return false;
}

async function getFailedAttempts() {
    const authData = await getFromStore(STORE_AUTH, 'passphrase_hash');
    return authData?.failedAttempts || 0;
}

async function wipeAllData() {
    const stores = [STORE_NOTES, STORE_ATTACHMENTS, STORE_AUTH];
    for (const store of stores) {
        const items = await getAllFromStore(store);
        for (const item of items) {
            await deleteFromStore(store, item.key || item.id);
        }
    }
}

// ============================================================
// NOTE OPERATIONS
// ============================================================
async function saveNote(noteId, title, content, attachments) {
    const encrypted = await encryptData(JSON.stringify({
        title,
        content,
        attachments: attachments || [],
        updated: new Date().toISOString()
    }), currentPassphrase);
    
    await putToStore(STORE_NOTES, {
        id: noteId,
        encrypted: encrypted,
        updated: new Date().toISOString()
    });
}

async function loadNote(noteId) {
    const note = await getFromStore(STORE_NOTES, noteId);
    if (!note) return null;
    
    const decrypted = await decryptData(note.encrypted, currentPassphrase);
    return JSON.parse(decrypted);
}

async function getAllNoteIds() {
    const notes = await getAllFromStore(STORE_NOTES);
    return notes.sort((a, b) => new Date(b.updated) - new Date(a.updated));
}

async function deleteNote(noteId) {
    await deleteFromStore(STORE_NOTES, noteId);
}

// ============================================================
// ATTACHMENT OPERATIONS
// ============================================================
async function saveAttachment(attachmentId, fileData, mimeType, originalName) {
    const encrypted = await encryptData(JSON.stringify({
        data: Array.from(new Uint8Array(fileData)),
        mimeType,
        originalName
    }), currentPassphrase);
    
    await putToStore(STORE_ATTACHMENTS, {
        id: attachmentId,
        encrypted: encrypted
    });
}

async function loadAttachment(attachmentId) {
    const attachment = await getFromStore(STORE_ATTACHMENTS, attachmentId);
    if (!attachment) return null;
    
    const decrypted = await decryptData(attachment.encrypted, currentPassphrase);
    const data = JSON.parse(decrypted);
    return {
        blob: new Blob([new Uint8Array(data.data)], { type: data.mimeType }),
        mimeType: data.mimeType,
        originalName: data.originalName
    };
}

async function deleteAttachment(attachmentId) {
    await deleteFromStore(STORE_ATTACHMENTS, attachmentId);
}

// ============================================================
// UI RENDERING
// ============================================================
async function refreshNotesList() {
    const notesList = document.getElementById('notes-list');
    const notesData = await getAllNoteIds();
    
    if (notesData.length === 0) {
        notesList.innerHTML = '<div class="empty-state">Belum ada catatan<br>Klik + untuk membuat</div>';
        return;
    }
    
    let html = '';
    for (const note of notesData) {
        let title = 'Untitled';
        try {
            const decrypted = await decryptData(note.encrypted, currentPassphrase);
            const data = JSON.parse(decrypted);
            title = data.title || 'Untitled';
        } catch(e) {}
        
        const activeClass = currentNoteId === note.id ? 'active' : '';
        html += `
            <div class="note-item ${activeClass}" data-id="${note.id}">
                <div class="note-item-title">${escapeHtml(title.substring(0, 40))}</div>
                <div class="note-item-date">${new Date(note.updated).toLocaleString()}</div>
            </div>
        `;
    }
    notesList.innerHTML = html;
    
    // Bind click events
    document.querySelectorAll('.note-item').forEach(el => {
        el.addEventListener('click', () => loadNoteToEditor(el.dataset.id));
    });
}

async function loadNoteToEditor(noteId) {
    currentNoteId = noteId;
    const noteData = await loadNote(noteId);
    
    if (noteData) {
        document.getElementById('note-title').value = noteData.title || '';
        document.getElementById('note-content').value = noteData.content || '';
        await refreshAttachmentsList(noteData.attachments || []);
    }
    
    await refreshNotesList();
}

async function refreshAttachmentsList(attachments) {
    const container = document.getElementById('attachment-list');
    
    if (!attachments || attachments.length === 0) {
        container.innerHTML = '<div class="empty-attachment">Belum ada gambar</div>';
        return;
    }
    
    let html = '';
    for (const att of attachments) {
        try {
            const attachmentData = await loadAttachment(att.id);
            if (attachmentData) {
                const url = URL.createObjectURL(attachmentData.blob);
                html += `
                    <div class="attachment-item" data-id="${att.id}">
                        <img src="${url}" class="attachment-thumb" alt="Thumbnail">
                        <div class="attachment-info">${escapeHtml(att.originalName.substring(0, 12))}</div>
                        <button class="attachment-delete" data-id="${att.id}">✕ Hapus</button>
                    </div>
                `;
            }
        } catch(e) {}
    }
    container.innerHTML = html;
    
    // Bind view full image
    document.querySelectorAll('.attachment-item').forEach(el => {
        el.addEventListener('click', (e) => {
            if (e.target.classList.contains('attachment-delete')) return;
            showFullImage(el.dataset.id);
        });
    });
    
    // Bind delete buttons
    document.querySelectorAll('.attachment-delete').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const attId = btn.dataset.id;
            await removeAttachment(attId);
        });
    });
}

async function addImageToNote() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        showLoading();
        try {
            const noteData = currentNoteId ? await loadNote(currentNoteId) : { title: '', content: '', attachments: [] };
            const attachments = noteData.attachments || [];
            
            const fileData = await file.arrayBuffer();
            const attachmentId = crypto.randomUUID();
            
            await saveAttachment(attachmentId, fileData, file.type, file.name);
            
            attachments.push({
                id: attachmentId,
                originalName: file.name,
                added: new Date().toISOString()
            });
            
            if (currentNoteId) {
                await saveNote(currentNoteId, noteData.title, noteData.content, attachments);
            } else {
                currentNoteId = crypto.randomUUID();
                await saveNote(currentNoteId, noteData.title, noteData.content, attachments);
            }
            
            await refreshAttachmentsList(attachments);
            await refreshNotesList();
            
        } catch (err) {
            alert('Gagal menambah gambar: ' + err.message);
        } finally {
            hideLoading();
        }
    };
    input.click();
}

async function removeAttachment(attachmentId) {
    if (!confirm('Hapus gambar ini?')) return;
    
    showLoading();
    try {
        const noteData = await loadNote(currentNoteId);
        if (noteData) {
            noteData.attachments = noteData.attachments.filter(a => a.id !== attachmentId);
            await saveNote(currentNoteId, noteData.title, noteData.content, noteData.attachments);
            await deleteAttachment(attachmentId);
            await refreshAttachmentsList(noteData.attachments);
        }
    } finally {
        hideLoading();
    }
}

async function showFullImage(attachmentId) {
    const attachment = await loadAttachment(attachmentId);
    if (!attachment) return;
    
    const url = URL.createObjectURL(attachment.blob);
    const modal = document.getElementById('image-modal');
    const img = document.getElementById('modal-image');
    const info = document.getElementById('modal-info');
    
    img.src = url;
    info.textContent = `${attachment.originalName} | ${Math.round(attachment.blob.size / 1024)} KB`;
    modal.style.display = 'flex';
    
    document.getElementById('modal-save').onclick = () => {
        const a = document.createElement('a');
        a.href = url;
        a.download = attachment.originalName;
        a.click();
    };
}

// ============================================================
// MAIN APP LOGIC
// ============================================================
async function login() {
    const passphrase = document.getElementById('passphrase-input').value;
    if (!passphrase) {
        alert('Masukkan passphrase');
        return;
    }
    
    showLoading();
    try {
        const isValid = await verifyPassphrase(passphrase);
        if (isValid) {
            currentPassphrase = passphrase;
            currentDecoyMode = false;
            await loadMainApp();
        } else {
            const attempts = await getFailedAttempts();
            if (attempts >= 3) {
                if (confirm('3 kali percobaan gagal! Hapus semua data?')) {
                    await wipeAllData();
                    alert('Data telah dihapus. Silakan buat passphrase baru.');
                    location.reload();
                }
            } else {
                const warning = document.getElementById('attempt-warning');
                warning.textContent = `⚠️ Passphrase salah! Sisa percobaan: ${3 - attempts}/3`;
                warning.style.display = 'block';
                document.getElementById('passphrase-input').value = '';
            }
        }
    } finally {
        hideLoading();
    }
}

async function loadMainApp() {
    showScreen('main-screen');
    document.getElementById('mode-badge').textContent = '🔐 SECURE VAULT';
    await refreshNotesList();
    
    // Clear editor
    document.getElementById('note-title').value = '';
    document.getElementById('note-content').value = '';
    document.getElementById('attachment-list').innerHTML = '<div class="empty-attachment">Belum ada gambar</div>';
    currentNoteId = null;
}

async function enterDecoyMode() {
    currentDecoyMode = true;
    currentPassphrase = 'decoy_mode_no_encryption';
    showScreen('main-screen');
    document.getElementById('mode-badge').textContent = '📦 DECOY MODE (No Encryption)';
    await refreshNotesList();
}

async function newNote() {
    currentNoteId = null;
    document.getElementById('note-title').value = '';
    document.getElementById('note-content').value = '';
    document.getElementById('attachment-list').innerHTML = '<div class="empty-attachment">Belum ada gambar</div>';
    document.getElementById('note-title').focus();
}

async function saveCurrentNote() {
    const title = document.getElementById('note-title').value.trim();
    const content = document.getElementById('note-content').value;
    
    if (!title && !content) {
        alert('Isi judul atau konten catatan');
        return;
    }
    
    showLoading();
    try {
        const noteData = currentNoteId ? await loadNote(currentNoteId) : null;
        const attachments = noteData?.attachments || [];
        
        if (!currentNoteId) {
            currentNoteId = crypto.randomUUID();
        }
        
        await saveNote(currentNoteId, title || 'Untitled', content, attachments);
        await refreshNotesList();
        alert('Catatan tersimpan');
    } finally {
        hideLoading();
    }
}

async function deleteCurrentNote() {
    if (!currentNoteId) {
        alert('Tidak ada catatan yang dipilih');
        return;
    }
    
    if (!confirm('Yakin ingin menghapus catatan ini beserta semua gambarnya?')) return;
    
    showLoading();
    try {
        const noteData = await loadNote(currentNoteId);
        if (noteData?.attachments) {
            for (const att of noteData.attachments) {
                await deleteAttachment(att.id);
            }
        }
        
        await deleteNote(currentNoteId);
        currentNoteId = null;
        document.getElementById('note-title').value = '';
        document.getElementById('note-content').value = '';
        document.getElementById('attachment-list').innerHTML = '<div class="empty-attachment">Belum ada gambar</div>';
        await refreshNotesList();
        alert('Catatan dan lampiran dihapus');
    } finally {
        hideLoading();
    }
}

async function emergencyWipe() {
    if (!confirm('⚠️ PERINGATAN AKHIR ⚠️\n\nSEMUA CATATAN DAN GAMBAR AKAN DIHAPUS PERMANEN\nTIDAK BISA DIKEMBALIKAN\n\nApakah Anda yakin?')) return;
    
    showLoading();
    try {
        await wipeAllData();
        alert('Semua data telah dihapus. Aplikasi akan mereset.');
        location.reload();
    } finally {
        hideLoading();
    }
}

async function logout() {
    currentPassphrase = null;
    currentNoteId = null;
    currentDecoyMode = false;
    showScreen('login-screen');
    document.getElementById('passphrase-input').value = '';
    document.getElementById('attempt-warning').style.display = 'none';
}

async function setupNewVault() {
    const pass1 = document.getElementById('new-passphrase').value;
    const pass2 = document.getElementById('confirm-passphrase').value;
    
    if (pass1.length < 8) {
        alert('Passphrase minimal 8 karakter');
        return;
    }
    if (pass1 !== pass2) {
        alert('Passphrase tidak cocok');
        return;
    }
    
    showLoading();
    try {
        await registerPassphrase(pass1);
        alert('Vault berhasil dibuat! Silakan login.');
        showScreen('login-screen');
        document.getElementById('passphrase-input').value = '';
    } finally {
        hideLoading();
    }
}

// ============================================================
// INITIALIZATION
// ============================================================
async function init() {
    await initDB();
    
    const hasAuth = await checkAuth();
    
    if (hasAuth === false) {
        showScreen('setup-screen');
    } else {
        showScreen('login-screen');
    }
    
    // Bind events
    document.getElementById('login-btn').onclick = login;
    document.getElementById('decoy-btn').onclick = enterDecoyMode;
    document.getElementById('wipe-btn').onclick = emergencyWipe;
    document.getElementById('setup-create-btn').onclick = setupNewVault;
    document.getElementById('new-note-btn').onclick = newNote;
    document.getElementById('logout-btn').onclick = logout;
    document.getElementById('wipe-main-btn').onclick = emergencyWipe;
    document.getElementById('save-note-btn').onclick = saveCurrentNote;
    document.getElementById('delete-note-btn').onclick = deleteCurrentNote;
    document.getElementById('add-image-btn').onclick = addImageToNote;
    document.getElementById('modal-close').onclick = () => {
        document.getElementById('image-modal').style.display = 'none';
    };
    document.getElementById('image-modal').onclick = (e) => {
        if (e.target === document.getElementById('image-modal')) {
            document.getElementById('image-modal').style.display = 'none';
        }
    };
    
    document.getElementById('passphrase-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') login();
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Start application
init();