import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { auth, db } from '../firebase'; // Sesuaikan path firebase config Anda
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword
} from 'firebase/auth';
import {
  collection,
  query,
  where,
  getDocs,
  doc,
  setDoc,
  getDoc
} from 'firebase/firestore';

export default function LoginPage() {
  const [identifier, setIdentifier] = useState(''); // NIM / NIDN / Username / Email
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setStatusMsg('');
    setLoading(true);

    try {
      const input = identifier.trim();
      let targetEmail = input;
      let existingUserData = null;
      let existingDocId = null;

      // 1. Cari data di Firestore (berdasarkan username, nim, nidn, atau email)
      const usersRef = collection(db, 'users');
      let snap;

      if (!input.includes('@')) {
        // Coba cari berdasarkan NIM
        snap = await getDocs(query(usersRef, where('nim', '==', input)));
        // Jika tidak ada, coba cari berdasarkan NIDN
        if (snap.empty) {
          snap = await getDocs(query(usersRef, where('nidn', '==', input)));
        }
        // Jika tidak ada, coba cari berdasarkan Username
        if (snap.empty) {
          snap = await getDocs(query(usersRef, where('username', '==', input)));
        }
      } else {
        // Cari berdasarkan Email
        snap = await getDocs(query(usersRef, where('email', '==', input)));
      }

      if (!snap.empty) {
        existingUserData = snap.docs[0].data();
        existingDocId = snap.docs[0].id;
        targetEmail = existingUserData.email || `${input.replace(/\s+/g, '')}@stienas.ac.id`;
      }

      let user = null;

      // 2. Coba login ke Firebase Authentication
      try {
        const userCredential = await signInWithEmailAndPassword(auth, targetEmail, password);
        user = userCredential.user;
      } catch (authErr) {
        // JIKA AKUN BELUM ADA DI FIREBASE AUTH -> LAKUKAN AUTO-SYNC!
        if (
          authErr.code === 'auth/user-not-found' ||
          authErr.code === 'auth/invalid-credential' ||
          authErr.code === 'auth/invalid-login-credentials'
        ) {
          if (existingUserData) {
            setStatusMsg('Menyinkronkan akun lama ke Firebase Auth...');

            // Daftarkan akun secara otomatis ke Firebase Auth
            const newCredential = await createUserWithEmailAndPassword(auth, targetEmail, password);
            user = newCredential.user;

            // Sinkronkan data ke Firestore dengan UID Firebase
            await setDoc(doc(db, 'users', user.uid), {
              ...existingUserData,
              email: targetEmail,
              uid: user.uid,
              syncedAt: new Date().toISOString()
            }, { merge: true });

          } else {
            throw new Error('Akun tidak ditemukan di data universitas.');
          }
        } else {
          throw authErr;
        }
      }

      // 3. Ambil role pengguna
      let role = '';
      const userDocRef = doc(db, 'users', user.uid);
      const userDocSnap = await getDoc(userDocRef);

      if (userDocSnap.exists()) {
        role = (userDocSnap.data().role || '').toLowerCase();
      } else if (existingUserData) {
        role = (existingUserData.role || '').toLowerCase();
      }

      // Simpan session lokal
      localStorage.setItem('user', JSON.stringify({
        uid: user.uid,
        email: targetEmail,
        role,
        ...(existingUserData || {})
      }));

      // 4. Redirect sesuai role
      if (role === 'admin' || role === 'superadmin') {
        navigate('/admin/dashboard');
      } else if (role === 'dosen') {
        navigate('/dosen/dashboard');
      } else if (role === 'mahasiswa') {
        navigate('/mahasiswa/dashboard');
      } else if (role === 'akademik') {
        navigate('/akademik/dashboard');
      } else {
        navigate('/dashboard');
      }

    } catch (err) {
      console.error('Login/Sync Error:', err);
      if (err.code === 'auth/wrong-password') {
        setError('Kata sandi salah.');
      } else if (err.code === 'auth/email-already-in-use') {
        setError('Email sudah terdaftar. Masukkan kata sandi yang sesuai.');
      } else {
        setError(err.message || 'Gagal login atau menyinkronkan akun.');
      }
    } finally {
      setLoading(false);
      setStatusMsg('');
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#f8fafc', padding: '16px' }}>
      <div style={{ maxWidth: '420px', width: '100%', background: '#fff', padding: '32px', borderRadius: '12px', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}>
        <h2 style={{ textAlign: 'center', fontWeight: 'bold', fontSize: '22px', marginBottom: '6px' }}>LMS STIENAS BJM</h2>
        <p style={{ textAlign: 'center', color: '#64748b', fontSize: '14px', marginBottom: '24px' }}>
          Portal Login Dosen, Mahasiswa, Akademik & Admin
        </p>

        {statusMsg && (
          <div style={{ background: '#e0f2fe', color: '#0369a1', padding: '10px', borderRadius: '6px', fontSize: '13px', marginBottom: '16px' }}>
            {statusMsg}
          </div>
        )}

        {error && (
          <div style={{ background: '#fee2e2', color: '#dc2626', padding: '10px', borderRadius: '6px', fontSize: '13px', marginBottom: '16px' }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px' }}>
              NIM / NIDN / Username / Email
            </label>
            <input
              type="text"
              required
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              placeholder="Contoh: NIM mahasiswa, NIDN dosen, atau email"
              style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid #cbd5e1', fontSize: '14px', boxSizing: 'border-box' }}
            />
          </div>

          <div style={{ marginBottom: '24px' }}>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '6px' }}>
              Kata Sandi
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Masukkan kata sandi akun Anda"
              style={{ width: '100%', padding: '10px 12px', borderRadius: '6px', border: '1px solid #cbd5e1', fontSize: '14px', boxSizing: 'border-box' }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{ width: '100%', padding: '12px', background: loading ? '#94a3b8' : '#2563eb', color: '#fff', border: 'none', borderRadius: '6px', fontSize: '15px', fontWeight: '600', cursor: loading ? 'not-allowed' : 'pointer' }}
          >
            {loading ? 'Memproses Masuk...' : 'Masuk ke Sistem'}
          </button>
        </form>
      </div>
    </div>
  );
}