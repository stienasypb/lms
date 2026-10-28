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

async function inspectUsers() {
  console.log('Fetching users from Firestore collection "users"...');
  try {
    const snap = await getDocs(collection(db, 'users'));
    console.log(`Found ${snap.size} user documents in Firestore:`);
    snap.docs.forEach((d, i) => {
      const data = d.data();
      console.log(`[${i+1}] ID: ${d.id} | Email: ${data.email} | Role: ${data.role} | Name: ${data.name} | Password: ${data.password ? '***' : '(none)'}`);
    });
  } catch (err) {
    console.error('Error fetching users:', err.message);
  }
  process.exit(0);
}

inspectUsers();
