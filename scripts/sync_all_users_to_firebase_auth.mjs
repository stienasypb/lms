import { initializeApp } from 'firebase/app';
import { getFirestore, collection, getDocs } from 'firebase/firestore';

const API_KEY = "AIzaSyDITlobzgm52tNwHUa7j5Z070DY4vJOJBw";
const firebaseConfig = {
  apiKey: API_KEY,
  authDomain: "lms-stienas.firebaseapp.com",
  projectId: "lms-stienas",
  storageBucket: "lms-stienas.firebasestorage.app",
  messagingSenderId: "1039609038510",
  appId: "1:1039609038510:web:18536257413fe47b448f3f"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

async function createAuthUser(email, password) {
  const url = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      password,
      returnSecureToken: true
    })
  });
  const data = await res.json();
  if (data.error) {
    if (data.error.message === 'EMAIL_EXISTS') {
      return { status: 'EXISTS', email };
    }
    return { status: 'ERROR', error: data.error.message, email };
  }
  return { status: 'CREATED', uid: data.localId, email };
}

async function syncAllUsers() {
  console.log('🚀 Memulai Sinkronisasi Seluruh Akun Firestore ke Firebase Authentication...\n');

  const snap = await getDocs(collection(db, 'users'));
  const users = snap.docs.map(d => ({ docId: d.id, ...d.data() }));

  // Tambahkan juga akun admin utama jika belum ada di list
  const hasSuperAdmin = users.some(u => (u.email || '').toLowerCase() === 'admin@stienas.ac.id');
  if (!hasSuperAdmin) {
    users.push({
      docId: 'user-admin-1',
      email: 'admin@stienas.ac.id',
      username: 'admin',
      role: 'SUPER_ADMIN',
      name: 'Administrator Sistem (Super Admin)',
      password: 'admin126',
      isActive: true
    });
  }

  console.log(`Ditemukan ${users.length} akun pengguna untuk didaftarkan ke Firebase Auth.\n`);

  let createdCount = 0;
  let existsCount = 0;
  let errorCount = 0;

  for (const u of users) {
    let email = (u.email || '').trim().toLowerCase();
    if (!email || !email.includes('@')) {
      if (u.username) {
        email = `${u.username.trim().toLowerCase()}@lms.stienas.ac.id`;
      } else if (u.nim) {
        email = `${String(u.nim).trim()}@lms.stienas.ac.id`;
      } else {
        console.log(`⚠️ Lewati akun tanpa email/username: ${u.name || u.docId}`);
        continue;
      }
    }

    // Koreksi typo domain jika ada (seperti .cok -> .com)
    if (email.endsWith('.cok')) {
      email = email.replace(/\.cok$/, '.com');
    }

    let password = (u.password || '').trim();
    if (!password || password.length < 6) {
      if ((u.role || '').toUpperCase().includes('ADMIN')) {
        password = 'admin126';
      } else if ((u.role || '').toUpperCase() === 'DOSEN') {
        password = 'stienas2026';
      } else {
        password = 'mhs12345';
      }
    }

    try {
      const res = await createAuthUser(email, password);

      if (res.status === 'CREATED') {
        console.log(`✅ [CREATED] ${u.name || email} (${email}) | Pass: ${password} | UID: ${res.uid}`);
        createdCount++;
      } else if (res.status === 'EXISTS') {
        console.log(`ℹ️ [EXISTS]  ${u.name || email} (${email}) sudah terdaftar di Firebase Auth.`);
        existsCount++;
      } else {
        console.error(`❌ [FAILED]  ${email}: ${res.error}`);
        errorCount++;
      }
    } catch (e) {
      console.error(`❌ [ERROR]   ${email}: ${e.message}`);
      errorCount++;
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log(`  SINKRONISASI SELESAI`);
  console.log(`  ✓ Akun Baru Dibuat di Firebase Auth : ${createdCount}`);
  console.log(`  ✓ Akun Sudah Ada di Firebase Auth   : ${existsCount}`);
  console.log(`  ✓ Gagal                            : ${errorCount}`);
  console.log('='.repeat(60));

  process.exit(0);
}

syncAllUsers().catch(err => {
  console.error('Fatal sync error:', err);
  process.exit(1);
});
