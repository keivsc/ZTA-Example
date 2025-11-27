export interface DBItem<T = any> {
  id: string;
  value: T;
}

export class LocalDB {
  private dbName: string;
  private version: number;

  constructor(dbName: string, version = 1) {
    this.dbName = dbName;
    this.version = version;
  }

  private open(storeName: string): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);

      request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(storeName)) {
          db.createObjectStore(storeName, { keyPath: 'id' });
        }
      };

      request.onsuccess = (event: Event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        resolve(db);
      };

      request.onerror = (event: Event) => {
        reject((event.target as IDBOpenDBRequest).error);
      };
    });
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
