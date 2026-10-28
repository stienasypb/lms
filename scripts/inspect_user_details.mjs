import { initializeApp } from 'firebase/app';
import { getFirestore, collection, getDocs } from 'firebase/firestore';

const firebaseConfig = {
  apiKey: "AIzaSyDITlobzgm52tNwHUa7j5Z070DY4vJOJBw",
  authDomain: "lms-stienas.firebaseapp.com",
  projectId: "lms-stienas",
  storageBucket: "lms-stienas.firebasestorage.app",
  messagingSenderId: "1039609038510",
  appId: "1:1039609038510:web:18536257413fe47b448f3f"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

async function inspectUserDetails() {
  const snap = await getDocs(collection(db, 'users'));
  const users = snap.docs.map(d => ({ id: d.id, ...d.data() }));
  console.log(JSON.stringify(users.map(u => ({
    id: u.id,
    email: u.email,
    username: u.username,
    nim: u.nim,
    nidn: u.nidn,
    role: u.role,
    password: u.password
  })), null, 2));
  process.exit(0);
}

inspectUserDetails();
