import Database from "../src/db.js";
import { fileToBlob, getFileType, hexToString } from "../src/utils.js";
import {randomUUID} from 'crypto';

const fileDb = new Database('files.db');

await fileDb.run(
  `CREATE TABLE IF NOT EXISTS files(
    fileId TEXT PRIMARY KEY,
    type TEXT,
    filename TEXT,
    size INTEGER,
    content TEXT,
    ownerId TEXT,
    createdAt INTEGER,
    lastModified INTEGER
  )`
)

await fileDb.run(
  `CREATE TABLE IF NOT EXISTS fileAccess(
    fileId TEXT PRIMARY KEY,
    userId TEXT,
    canRead BOOLEAN,
    canWrite BOOLEAN
  )`
)



export async function getFile(fileId, userId) {
  const row = await fileDb.get(
    `
    SELECT 
      f.fileId,
      f.filename,
      f.size,
      f.type,
      f.ownerId,
      f.createdAt,
      f.lastModified,
      fa.canRead,
      fa.canWrite,
      CASE WHEN fa.canRead = 1 OR f.ownerId = ? THEN f.content ELSE NULL END AS content
    FROM files f
    LEFT JOIN fileAccess fa ON f.fileId = fa.fileId AND fa.userId = ?
    WHERE f.fileId = ?
  `,
    [userId, userId, fileId]
  )

  if (!row) return { error: "File does not exist." }

  if (!row.canRead && row.ownerId !== userId) {
    return {}
  }

  const isOwner = row.ownerId === userId

  const contentString = row.content ? hexToString(row.content) : ''

  return {
    fileId: row.fileId,
    filename: row.filename,
    size: row.size,
    type: row.type,
    content: contentString,
    ownerId: row.ownerId,
    createdAt: row.createdAt,
    lastModified: row.lastModified,
    canRead: isOwner ? true : !!row.canRead,
    canWrite: isOwner ? true : !!row.canWrite
  }
}

export async function createFile(filename, userId, users){

  const fileType = getFileType(filename);
  const {fileCount} = await fileDb.get(
    `SELECT COUNT(*) as fileCount from files WHERE ownerId = ?`,
    [userId]
  );
  if (fileCount >= 5){
    return {success:false, error:'Too many files created.'}
  }
  const fileId = randomUUID()
  await fileDb.run(
    `INSERT INTO files(fileId, filename, type, size, content, ownerId, createdAt, lastModified)
    VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
    [fileId, filename, fileType, 0, "", userId, Date.now(), Date.now()]
  );

  await updatePermissions(fileId, users);

  return {success:true, fileId};

}

export async function updateFile(fileId, userId, content){
  const fileAccess = await fileDb.get(
    `SELECT 
      CASE 
        WHEN f.ownerId = ? THEN 1
        ELSE fa.canWrite
      END AS hasWriteAccess
    FROM files f
    LEFT JOIN fileAccess fa ON f.fileId = fa.fileId AND fa.userId = ?
    WHERE f.fileId = ?`,
    [userId, userId, fileId]
  );

  if (!fileAccess){
    return {sucess:false, error:"Invalid fileId / Missing permissions"}
  }

  try{
    const contentBlob = fileToBlob(content);
    const arrayBuffer = await contentBlob.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const contentHex = buffer.toString('hex');
    await fileDb.run(
      `UPDATE files SET content = ? WHERE fileId = ?`,
      [contentHex, fileId]
    )
  return {success:true, fileId};
  }catch(err){
    return {success:false, error:err.message}
  }

}

export async function deleteFile(fileId, userId){
  const isOwner = await fileDb.get(
    `SELECT 1 FROM files WHERE ownerId = ? AND fileId = ?`,
    [userId, fileId]
  );

  if (!isOwner){
    return {success:false, error:"File does not exist."}
  }

  await fileDb.run(
    `DELETE FROM files WHERE fileId = ?`,
    [fileId]
  );
  await fileDb.run(
    `DELETE FROM fileAccess WHERE fileId = ?`,
    [fileId]
  );
  return {success:true};

}

export async function updatePermissions(fileId, ownerUserId, users) {
    const file = await fileDb.get(
        `SELECT ownerId FROM files WHERE fileId = ?`,
        [fileId]
    );

    if (!file) {
        return { success: false, error: "File does not exist." };
    }

    if (file.ownerId !== ownerUserId) {
        return { success: false, error: "Only the owner can change permissions." };
    }

    if (!Array.isArray(users) || users.length === 0) {
        return { success: false, error: "Users not an array or is not included." };
    }

    const now = Date.now();

    for (const u of users) {
        const { userId, read, write } = u;

        const existing = await fileDb.get(
            `SELECT * FROM fileAccess WHERE fileId = ? AND userId = ?`,
            [fileId, userId]
        );

        if (existing) {
            await fileDb.run(
                `UPDATE fileAccess 
                 SET canRead = ?, canWrite = ?, updatedAt = ? 
                 WHERE fileId = ? AND userId = ?`,
                [read ? 1 : 0, write ? 1 : 0, now, fileId, userId]
            );
        } else {
            await fileDb.run(
                `INSERT INTO fileAccess (fileId, userId, canRead, canWrite, createdAt, updatedAt)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [fileId, userId, read ? 1 : 0, write ? 1 : 0, now, now]
            );
        }
    }

    return { success: true, users };
}

export async function getAllFiles(userId) {
    const rows = await fileDb.getAll(
        `
        SELECT 
            f.fileId,
            f.filename AS name,
            f.size,
            CASE 
                WHEN f.ownerId = ? THEN 1
                ELSE fa.canRead
            END AS canRead,
            CASE 
                WHEN f.ownerId = ? THEN 1
                ELSE fa.canWrite
            END AS canWrite
        FROM files f
        LEFT JOIN fileAccess fa ON f.fileId = fa.fileId AND fa.userId = ?
        WHERE f.ownerId = ? OR fa.canRead = 1
        `,
        [userId, userId, userId, userId]
    );

    return rows.map(row => ({
        fileId: row.fileId,
        filename: row.name,
        size: row.size,
        canRead: !!row.canRead,
        canWrite: !!row.canWrite
    }));
}


