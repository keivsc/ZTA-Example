export interface DBItem<T = any> {
  id: string;
  value: T;
}

export class LocalDB {
  private dbName: string;
  private version: number;
  private dbCache: Map<string, IDBDatabase>; // cache per store

  constructor(dbName: string, version = 1) {
    this.dbName = dbName;
    this.version = version;
    this.dbCache = new Map();
  }

  private async open(storeName: string): Promise<IDBDatabase> {
    // Return cached DB if already opened for this store
    if (this.dbCache.has(storeName)) {
      return this.dbCache.get(storeName)!;
    }

    while (true) {
      try {
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const request = indexedDB.open(this.dbName, this.version);

          request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
            const db = (event.target as IDBOpenDBRequest).result;
            if (!db.objectStoreNames.contains(storeName)) {
              db.createObjectStore(storeName, { keyPath: 'id' });
            }
          };

          request.onsuccess = (event: Event) => {
            resolve((event.target as IDBOpenDBRequest).result);
          };

          request.onerror = (event: Event) => {
            reject((event.target as IDBOpenDBRequest).error);
          };
        });

        if (db.objectStoreNames.contains(storeName)) {
          // Cache DB for future calls
          this.dbCache.set(storeName, db);
          return db;
        }

        // If store missing, bump version and retry
        db.close();
        this.version++;
      } catch (err) {
        // If version conflict or other error, bump version and retry
        this.version++;
      }
    }
  }

  async addItem<T>(storeName: string, item: DBItem<T>): Promise<void> {
    const db = await this.open(storeName);
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    store.put(item);
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async getItem<T>(storeName: string, id: string): Promise<T | null> {
    const db = await this.open(storeName);
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    return new Promise((resolve, reject) => {
      const request = store.get(id);
      request.onsuccess = () => resolve((request.result as DBItem<T>)?.value ?? null);
      request.onerror = () => reject(request.error);
    });
  }

  async removeItem(storeName: string, id: string): Promise<void> {
    const db = await this.open(storeName);
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    store.delete(id);
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
}
