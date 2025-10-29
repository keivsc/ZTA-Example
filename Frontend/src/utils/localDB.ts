import { openDB } from 'idb';

export async function getKeyDB() {
  const db = await openDB('user-keys', 1, {
    upgrade(db) {
      db.createObjectStore('keys');
    }
  });
  return db;
}