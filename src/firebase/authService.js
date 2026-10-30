/**
 * Layanan Autentikasi Firebase & Otorisasi Pengguna
 * Sesuai PRD FR-01 (Login, State Persistence, Inactive Account Check)
 */
import { 
  signInWithEmailAndPassword, 
  createUserWithEmailAndPassword,
  signOut as firebaseSignOut, 
  onAuthStateChanged,
  sendPasswordResetEmail 
} from "firebase/auth";
import { doc, getDoc, setDoc, updateDoc, collection, getDocs } from "firebase/firestore";
import { auth, db, isRealFirebaseConfigured } from "./config.js";
import { INITIAL_USERS } from "../utils/seedData.js";
import { getUsers, isUserDeleted, setLocal, STORAGE_KEYS } from "./firestoreService.js";

// Helper konversi username/NIM/NIDN ke email standard jika bukan format email
export function normalizeLoginIdentifier(identifier) {
  const trimmed = (identifier || '').trim().toLowerCase();
  if (trimmed.includes('@')) {
    return trimmed;
  }
  // Format NIM / NIDN ke email domain LMS STIE Nasional
  return `${trimmed}@lms.stienas.ac.id`;
}

function describeFirebaseLoginError(error) {
  switch (error?.code) {
    case 'auth/invalid-credential':
    case 'auth/wrong-password':
    case 'auth/user-not-found':
      return 'Email atau kata sandi tidak cocok, atau akun belum dibuat di Firebase Authentication. Akun dari data lokal lama tidak otomatis menjadi akun Firebase.';
    case 'auth/too-many-requests':
      return 'Login sementara dibatasi karena terlalu banyak percobaan. Coba lagi beberapa saat atau gunakan Lupa Kata Sandi.';
    case 'auth/network-request-failed':
      return 'Tidak dapat terhubung ke Firebase Authentication. Periksa koneksi internet lalu coba lagi.';
    case 'auth/operation-not-allowed':
      return 'Login email/kata sandi belum diaktifkan pada Firebase Authentication project ini.';
    default:
      return 'Login Firebase gagal. Periksa email, kata sandi, dan koneksi akun Firebase Anda.';
  }
}

/**
 * Resolve profil LMS dari Firebase Auth user.
 * Catatan Penting: Firestore koleksi 'users' menyimpan dokumen dengan ID kustom
 * (mis. 'user-admin-1', 'user-mhs-1789...'), BUKAN Firebase Auth UID, sehingga
 * pencocokan profil harus dilakukan dengan:
 *   1. Dokumen langsung bernama auth UID, lalu
 *   2. Pencarian menyeluruh dokumen users yang cocok (email / username / NIM / NIDN / uid).
 */
export async function resolveFirebaseUserProfile(firebaseUser) {
  if (!firebaseUser) return null;

  const authUid = String(firebaseUser.uid || '');
  const authEmail = String(firebaseUser.email || '').toLowerCase().trim();

  // 1. Coba dokumen langsung dengan Firebase Auth UID sebagai doc id
  try {
    const snap = await getDoc(doc(db, 'users', authUid));
    if (snap.exists() && snap.data().role) {
      return { id: snap.id, uid: snap.id, ...snap.data() };
    }
  } catch (e) {
    console.warn('resolveFirebaseUserProfile: gagal membaca dokumen by auth uid:', e);
  }

  // 2. Cari dokumen users yang cocok via email / username / NIM / NIDN / uid
  try {
    const snap = await getDocs(collection(db, 'users'));
    for (const d of snap.docs) {
      const uData = { id: d.id, uid: d.id, ...d.data() };
      const uEmail = String(uData.email || '').toLowerCase().trim();
      const uUser = String(uData.username || '').toLowerCase().trim();
      const uNim = String(uData.nim || '').toLowerCase().trim();
      const uNidn = String(uData.nidn || '').toLowerCase().trim();
      const uKeys = [
        uEmail, uUser, uNim, uNidn,
        String(uData.uid || uData.id || uData.email || '')
      ]
        .filter(k => k && String(k).trim().length > 0)
        .map(k => String(k).toLowerCase());
      const targetKeys = [authEmail, authUid]
        .filter(k => k && String(k).trim().length > 0)
        .map(k => String(k).toLowerCase());
      const isMatch = targetKeys.some(tk => uKeys.includes(tk));
      if (isMatch) {
        uData.email = uEmail;
        uData.uid = uData.uid || uData.id;
        uData.id = uData.id || uData.uid;
        return uData;
      }
    }
  } catch (e) {
    console.warn('resolveFirebaseUserProfile: gagal scan koleksi users:', e);
  }

  return null;
}

// =========================================================================
// MEKANISME SESSION TIMEOUT & INACTIVITY TIMEOUT (15 MENIT)
// =========================================================================
export const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 Menit Inactive Timeout
export const WARNING_BEFORE_TIMEOUT_MS = 2 * 60 * 1000; // Peringatan 2 Menit sebelum timeout

export function recordUserActivity() {
  try {
    localStorage.setItem('STIE_LMS_LAST_ACTIVITY', Date.now().toString());
  } catch (e) {}
}

/**
 * Login dengan Email / NIM / NIDN + Password
 */
export async function loginUser(identifier, password) {
  const rawId = (identifier || '').trim();
  const trimmed = rawId.toLowerCase();
  const rawPass = (password || '').trim();

  if (!rawId) {
    throw new Error("Silakan masukkan Email, Username, NIM, atau NUPTK/NIP Anda.");
  }
  if (!rawPass) {
    throw new Error("Silakan masukkan kata sandi akun Anda.");
  }

  // 1. Kumpulkan seluruh pengguna dengan memuat dari database (Firestore + local) dan INITIAL_USERS
  let remoteUsers = [];
  try {
    remoteUsers = await getUsers();
  } catch (e) {
    remoteUsers = [];
  }

  const userMap = new Map();
  // 1. Baseline: INITIAL_USERS
  INITIAL_USERS.forEach(u => {
    const key = u.uid || u.id || u.email;
    if (key) userMap.set(String(key).toLowerCase(), { ...u });
  });

  // 2. Cache lokal sebagai fallback
  try {
    const stored = localStorage.getItem('STIE_LMS_USERS');
    if (stored) {
      const parsed = JSON.parse(stored);
      if (Array.isArray(parsed)) {
        parsed.forEach(storedU => {
          const { password, ...safeStoredUser } = storedU;
          storedU = safeStoredUser;
          const key = storedU.uid || storedU.id || storedU.email;
          if (key) {
            const existing = userMap.get(String(key).toLowerCase());
            userMap.set(String(key).toLowerCase(), { ...(existing || {}), ...storedU });
          }
        });
      }
    }
  } catch (e) {}

  // 3. Data terbaru dari Cloud Firestore (OTORITATIF - menimpa cache lokal lama)
  if (Array.isArray(remoteUsers) && remoteUsers.length > 0) {
    remoteUsers.forEach(u => {
      const key = u.uid || u.id || u.email;
      if (key) {
        const existing = userMap.get(String(key).toLowerCase());
        userMap.set(String(key).toLowerCase(), { ...(existing || {}), ...u });
      }
    });
  }

  let combinedUsers = Array.from(userMap.values());

  // Pastikan akun yang ada di daftar terhapus difilter (kecuali akun inti sistem yang dilindungi)
  try {
    const delRaw = localStorage.getItem('STIE_LMS_DELETED_USERS');
    if (delRaw) {
      const delList = JSON.parse(delRaw);
      if (Array.isArray(delList) && delList.length > 0) {
        combinedUsers = combinedUsers.filter(u => !isUserDeleted(u, delList));
      }
    }
  } catch (e) {}

  // 2. Cari pengguna yang cocok secara tepat berdasarkan email, username, NIM, atau NIDN
  let foundUser = combinedUsers.find(u => {
    const uEmail = (u.email || '').toLowerCase().trim();
    const uUser = (u.username || '').toLowerCase().trim();
    const uNim = String(u.nim || '').trim().toLowerCase();
    const uNidn = String(u.nidn || '').trim().toLowerCase();
    const uRole = (u.role || '').toUpperCase();

    // Pencocokan tepat berdasarkan email
    if (uEmail && uEmail === trimmed) return true;
    // Pencocokan tepat berdasarkan username
    if (uUser && uUser === trimmed) return true;
    // Pencocokan tepat berdasarkan NIM
    if (uNim && uNim === trimmed) return true;
    // Pencocokan tepat berdasarkan NIDN
    if (uNidn && uNidn === trimmed) return true;

    // Pencocokan email resmi Super Admin
    if (
      (trimmed === 'admin@stienas.ac.id') &&
      (uRole === 'SUPER_ADMIN' || uRole === 'ADMIN')
    ) {
      return true;
    }

    // Pencocokan email resmi BAA
    if (
      (trimmed === 'akademik@stienas.ac.id') &&
      (uRole === 'ADMIN_AKADEMIK' || uRole === 'BAA')
    ) {
      return true;
    }

    return false;
  });

  // Jika belum ditemukan di cache, cari langsung di koleksi 'users' Cloud Firestore
  if (!foundUser && isRealFirebaseConfigured() && db) {
    try {
      const snap = await getDocs(collection(db, "users"));
      for (const d of snap.docs) {
        const uData = { id: d.id, uid: d.id, ...d.data() };
        const uEmail = (uData.email || '').toLowerCase().trim();
        const uUser = (uData.username || '').toLowerCase().trim();
        const uNim = String(uData.nim || '').trim().toLowerCase();
        if (uEmail === trimmed || uUser === trimmed || uNim === trimmed) {
          foundUser = uData;
          combinedUsers.push(uData);
          break;
        }
      }
    } catch (e) {
      console.warn("Direct Firestore search error on login:", e);
    }
  }

  // Jika cocok di database pengguna lokal:
  if (foundUser) {
    if (foundUser.isActive === false) {
      throw new Error("Akun Anda berstatus non-aktif / dibekukan. Silakan hubungi Administrator STIE Nasional.");
    }

    // Jika akun Firebase Auth tersedia, gunakan sesi Firebase sebagai sumber
    // otorisasi Firestore.
    if (isRealFirebaseConfigured() && auth && foundUser.email) {
      const targetEmail = foundUser.email.toLowerCase().trim();
      let firebaseUser = null;

      try {
        const userCredential = await signInWithEmailAndPassword(
          auth,
          targetEmail,
          rawPass
        );
        firebaseUser = userCredential.user;
      } catch (firebaseError) {
        console.warn('Firebase Auth sign in failed, memeriksa opsi auto-sync:', firebaseError.code || firebaseError.message);

        // Jika akun belum dibuat di Firebase Auth, lakukan auto-registration / migrasi otomatis
        if (
          firebaseError.code === 'auth/user-not-found' ||
          firebaseError.code === 'auth/invalid-credential' ||
          firebaseError.code === 'auth/invalid-login-credentials'
        ) {
          if (rawPass.length < 6) {
            throw new Error('Kata sandi untuk autentikasi Firebase minimal 6 karakter. Silakan periksa kembali kata sandi akun Anda.');
          }

          try {
            // Otomatis daftarkan akun ke Firebase Auth
            const newCredential = await createUserWithEmailAndPassword(
              auth,
              targetEmail,
              rawPass
            );
            firebaseUser = newCredential.user;
            console.log('Akun berhasil di-auto-sync ke Firebase Auth:', targetEmail);
          } catch (createErr) {
            if (createErr.code === 'auth/email-already-in-use') {
              // Jika email sudah terdaftar di Firebase Auth tapi signIn gagal, berarti password salah
              throw new Error('Kata sandi yang Anda masukkan salah. Silakan periksa kembali kata sandi akun Anda.');
            }
            throw new Error(describeFirebaseLoginError(createErr));
          }
        } else {
          throw new Error(describeFirebaseLoginError(firebaseError));
        }
      }

      if (firebaseUser) {
        // Ambil profil dari Firestore (dengan fallback pencarian multi-kriteria
        // karena ID dokumen users bisa berupa custom ID seperti 'user-admin-1')
        let profile = null;
        try {
          profile = await resolveFirebaseUserProfile(firebaseUser);
        } catch (e) {
          console.warn('Gagal membaca profil dari Firestore:', e);
        }

        // Jika dokumen profil belum ada di Firestore (misalnya akun baru disinkronkan),
        // otomatis buatkan dokumen profil dari data foundUser!
        if (!profile || !profile.role) {
          const syncData = {
            ...foundUser,
            uid: firebaseUser.uid,
            id: firebaseUser.uid,
            email: targetEmail,
            syncedAt: new Date().toISOString()
          };
          delete syncData.password;

          try {
            await setDoc(doc(db, 'users', firebaseUser.uid), syncData, { merge: true });
            profile = syncData;
          } catch (errSet) {
            console.warn('Gagal menyimpan profil sync ke Firestore:', errSet);
            profile = syncData;
          }
        }

        if (profile.isActive === false) {
          await firebaseSignOut(auth);
          throw new Error('Akun Anda berstatus non-aktif / dibekukan. Silakan hubungi Administrator STIE Nasional.');
        }

        const cloudUser = {
          ...profile,
          uid: profile.uid || profile.id || firebaseUser.uid,
          id: profile.id || profile.uid || firebaseUser.uid,
          email: firebaseUser.email || profile.email
        };
        localStorage.setItem('STIE_LMS_ACTIVE_USER', JSON.stringify(cloudUser));
        recordUserActivity();
        localStorage.removeItem('STIE_LMS_SESSION_EXPIRED');
        return cloudUser;
      }
    }
    throw new Error('Akun ini belum dapat digunakan karena Firebase Authentication belum aktif.');
  }

  // 3. Jika tidak ditemukan di lokal dan Firebase asli dikonfigurasi:
  if (isRealFirebaseConfigured() && auth) {
    try {
      const normalizedEmail = normalizeLoginIdentifier(identifier);
      const userCredential = await signInWithEmailAndPassword(auth, normalizedEmail, rawPass);
      const user = userCredential.user;

      let userData = await resolveFirebaseUserProfile(user);

      if (!userData || !userData.role) {
        // Cari apakah ada data awal yang cocok dengan email ini di INITIAL_USERS
        const matchSeed = INITIAL_USERS.find(
          u => (u.email || '').toLowerCase() === normalizedEmail.toLowerCase()
        );
        if (matchSeed) {
          const syncData = {
            ...matchSeed,
            uid: user.uid,
            id: user.uid,
            email: normalizedEmail,
            syncedAt: new Date().toISOString()
          };
          delete syncData.password;
          try {
            await setDoc(doc(db, 'users', user.uid), syncData, { merge: true });
            userData = syncData;
          } catch (e) {
            userData = syncData;
          }
        }
      }

      if (userData) {
        if (userData.isActive === false) {
          await firebaseSignOut(auth);
          throw new Error("Akun Anda berstatus non-aktif. Silakan hubungi Administrator STIE Nasional.");
        }
        const fullProfile = { uid: user.uid, ...userData };
        localStorage.setItem('STIE_LMS_ACTIVE_USER', JSON.stringify(fullProfile));
        recordUserActivity();
        localStorage.removeItem('STIE_LMS_SESSION_EXPIRED');
        return fullProfile;
      } else {
        await firebaseSignOut(auth);
        throw new Error('Akun Firebase ini belum memiliki profil LMS. Hubungi administrator untuk menautkan akun dan peran Anda.');
      }
    } catch (fbErr) {
      console.warn("Firebase sign in error:", fbErr);
      if (fbErr.message?.includes('belum memiliki profil LMS') || fbErr.message?.includes('berstatus non-aktif')) throw fbErr;
      throw new Error(describeFirebaseLoginError(fbErr));
    }
  }

  throw new Error(`Akun dengan identitas '${identifier}' tidak ditemukan. Silakan periksa kembali atau pilih salah satu akun uji.`);
}

/**
 * Logout
 */
export async function logoutUser() {
  localStorage.removeItem('STIE_LMS_ACTIVE_USER');
  localStorage.removeItem('STIE_LMS_LAST_ACTIVITY');
  if (isRealFirebaseConfigured() && auth) {
    try {
      await firebaseSignOut(auth);
    } catch (e) {
      console.warn("Sign out error:", e);
    }
  }
}

/**
 * Dapatkan user tersimpan dari local state dengan validasi Session Inactivity Timeout
 */
export function getCurrentUser() {
  // Saat Firebase terkonfigurasi, sesi lokal tidak boleh menjadi bukti login.
  // Profil lokal lama hanya boleh dipakai oleh mode demo tanpa Firebase.
  if (isRealFirebaseConfigured()) return null;
  try {
    const saved = localStorage.getItem('STIE_LMS_ACTIVE_USER');
    if (!saved) return null;

    // Verifikasi batas waktu ketidakaktifan (Session Timeout 15 menit)
    const lastActivity = localStorage.getItem('STIE_LMS_LAST_ACTIVITY');
    if (lastActivity) {
      const elapsed = Date.now() - parseInt(lastActivity, 10);
      if (elapsed > SESSION_TIMEOUT_MS) {
        localStorage.removeItem('STIE_LMS_ACTIVE_USER');
        localStorage.removeItem('STIE_LMS_LAST_ACTIVITY');
        localStorage.setItem('STIE_LMS_SESSION_EXPIRED', 'true');
        return null;
      }
    } else {
      // Jika belum ada stempel aktivitas, catat saat ini
      recordUserActivity();
    }

    return JSON.parse(saved);
  } catch (e) {
    console.error("Gagal membaca active user:", e);
  }
  return null;
}

/**
 * Permintaan Reset Kata Sandi - Kirim tautan ke email resmi yang terdaftar
 * Mendukung pencarian berdasarkan Email, NIM, atau Username
 */
export async function requestPasswordReset(identifier) {
  const rawId = (identifier || '').trim();
  const trimmed = rawId.toLowerCase();

  if (!rawId) {
    throw new Error("Silakan masukkan alamat email, NIM, atau username akun Anda.");
  }

  // 1. Kumpulkan seluruh pengguna dengan memadukan INITIAL_USERS, remote users, dan data lokal
  let remoteUsers = [];
  try {
    remoteUsers = await getUsers();
  } catch (e) {
    remoteUsers = [];
  }

  const userMap = new Map();
  INITIAL_USERS.forEach(u => {
    const key = u.uid || u.id || u.email;
    if (key) userMap.set(String(key).toLowerCase(), { ...u });
  });

  if (Array.isArray(remoteUsers)) {
    remoteUsers.forEach(u => {
      const key = u.uid || u.id || u.email;
      if (key) {
        const existing = userMap.get(String(key).toLowerCase());
        userMap.set(String(key).toLowerCase(), { ...(existing || {}), ...u });
      }
    });
  }

  try {
    const stored = localStorage.getItem('STIE_LMS_USERS');
    if (stored) {
      const parsed = JSON.parse(stored);
      if (Array.isArray(parsed)) {
        parsed.forEach(storedU => {
          const key = storedU.uid || storedU.id || storedU.email;
          if (key) {
            const existing = userMap.get(String(key).toLowerCase());
            userMap.set(String(key).toLowerCase(), { ...(existing || {}), ...storedU });
          }
        });
      }
    }
  } catch (e) {}

  let combinedUsers = Array.from(userMap.values());

  // 2. Cari pengguna berdasarkan Email, Alias, Username, NIM, atau NIDN
  let foundUser = combinedUsers.find(u => {
    const uEmail = (u.email || '').toLowerCase().trim();
    const uAlias = (u.aliasEmail || '').toLowerCase().trim();
    const uUser = (u.username || '').toLowerCase().trim();
    const uNim = String(u.nim || '').trim().toLowerCase();
    const uNidn = String(u.nidn || '').trim().toLowerCase();

    return (
      (uEmail && (uEmail === trimmed || uAlias.split(/[\s,]+/).includes(trimmed))) ||
      (uUser && uUser === trimmed) ||
      (uNim && uNim === trimmed) ||
      (uNidn && uNidn === trimmed)
    );
  });

  // Jika belum ditemukan di cache, cari langsung di koleksi 'users' Cloud Firestore
  if (!foundUser && isRealFirebaseConfigured() && db) {
    try {
      const snap = await getDocs(collection(db, "users"));
      for (const d of snap.docs) {
        const uData = { id: d.id, uid: d.id, ...d.data() };
        const uEmail = (uData.email || '').toLowerCase().trim();
        const uUser = (uData.username || '').toLowerCase().trim();
        const uNim = String(uData.nim || '').trim().toLowerCase();
        const uNidn = String(uData.nidn || '').trim().toLowerCase();
        if (uEmail === trimmed || uUser === trimmed || uNim === trimmed || uNidn === trimmed) {
          foundUser = uData;
          break;
        }
      }
    } catch (e) {
      console.warn("Direct Firestore search error on password reset:", e);
    }
  }

  let targetEmail = null;
  if (foundUser && foundUser.email) {
    targetEmail = foundUser.email.trim();
  } else if (trimmed.includes('@')) {
    targetEmail = trimmed;
  }

  if (!foundUser && !targetEmail) {
    throw new Error(`Akun dengan identitas '${identifier}' tidak ditemukan dalam basis data LMS STIE Nasional.`);
  }

  if (foundUser && foundUser.isActive === false) {
    throw new Error("Akun ini dalam status non-aktif / dibekukan. Silakan hubungi Bagian Administrasi Akademik (BAA).");
  }

  let sentViaFirebase = false;

  // 3. Kirim reset password via Firebase Auth jika terkonfigurasi
  if (isRealFirebaseConfigured() && auth && targetEmail) {
    try {
      await sendPasswordResetEmail(auth, targetEmail);
      sentViaFirebase = true;
    } catch (fbErr) {
      console.warn("Firebase sendPasswordResetEmail notice:", fbErr.code || fbErr.message);
    }
  }

  // 4. Catat permintaan ke riwayat permintaan reset di localStorage agar Admin/BAA dapat memantau jika perlu
  try {
    const resetRequestsKey = 'STIE_LMS_RESET_REQUESTS';
    const rawReqs = localStorage.getItem(resetRequestsKey);
    const requests = rawReqs ? JSON.parse(rawReqs) : [];
    requests.unshift({
      id: `reset-${Date.now()}`,
      email: targetEmail,
      name: foundUser?.name || 'Pengguna LMS',
      identifierProvided: identifier,
      sentViaFirebase,
      timestamp: new Date().toISOString()
    });
    localStorage.setItem(resetRequestsKey, JSON.stringify(requests.slice(0, 50)));
  } catch (e) {
    console.warn("Save reset request error:", e);
  }

  return {
    success: true,
    email: targetEmail,
    name: foundUser?.name || targetEmail,
    sentViaFirebase,
    foundUser: foundUser ? {
      uid: foundUser.uid || foundUser.id,
      name: foundUser.name,
      email: foundUser.email,
      nim: foundUser.nim,
      role: foundUser.role
    } : null
  };
}

/**
 * Reset Kata Sandi Langsung secara Aman (Self-Service Direct Password Reset)
 * - Mode Firebase (produksi): kirim tautan reset password ke email akun via Firebase Auth
 * - Mode lokal / demo: atur kata sandi langsung pada akun lokal
 */
export async function directResetPassword(identifier, newPassword) {
  const rawId = (identifier || '').trim();
  const trimmed = rawId.toLowerCase();
  const cleanPass = (newPassword || '').trim();

  if (!rawId) {
    throw new Error("Identitas pengguna tidak boleh kosong.");
  }
  if (!cleanPass || cleanPass.length < 6) {
    throw new Error("Kata sandi baru minimal 6 karakter.");
  }

  // Mode produksi / Firebase: kirim tautan reset password ke alamat email akun
  if (isRealFirebaseConfigured() && auth) {
    const targetEmail = trimmed.includes('@') ? trimmed : `${trimmed}@lms.stienas.ac.id`;
    await sendPasswordResetEmail(auth, targetEmail);
    return { success: true, email: targetEmail, sentViaFirebase: true, method: 'RESET_EMAIL' };
  }

  // Mode lokal / demo: atur kata sandi langsung pada akun lokal
  const list = await getUsers();
  const target = list.find(u => 
    (u.email && u.email.toLowerCase().trim() === trimmed) ||
    (u.aliasEmail && u.aliasEmail.toLowerCase().trim() === trimmed) ||
    (u.username && u.username.toLowerCase().trim() === trimmed) ||
    (u.nim && String(u.nim).trim().toLowerCase() === trimmed) ||
    (u.nidn && String(u.nidn).trim().toLowerCase() === trimmed) ||
    (u.uid && String(u.uid) === rawId) ||
    (u.id && String(u.id) === rawId)
  );

  if (!target) {
    throw new Error(`Akun dengan identitas '${identifier}' tidak ditemukan dalam sistem.`);
  }

  const targetUid = target.uid || target.id;
  const updatedList = list.map(u => {
    const sameUid = u.uid === targetUid || u.id === targetUid;
    const sameEmail = u.email && String(u.email).toLowerCase().trim() === String(target.email || '').toLowerCase().trim();
    if (sameUid || sameEmail) {
      return { ...u, password: cleanPass };
    }
    return u;
  });

  await setLocal(STORAGE_KEYS.USERS, updatedList);
  return { success: true, email: target.email, sentViaFirebase: false, method: 'LOCAL' };
}

export { registerStudent } from './firestoreService.js';

