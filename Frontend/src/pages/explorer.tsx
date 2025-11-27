// FileManager.tsx
import { useEffect, useState } from "react";
import { createFile, getAllFiles, type user, type userPermission } from "../utils/api";

interface FileItem {
  fileId: string;
  filename: string;
  size: number; // in bytes
}

function FileManager() {
  const [files, setFiles] = useState<FileItem[]>([]);
  const [users, setUsers] = useState<user[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [newFilename, setNewFilename] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [permissions, setPermissions] = useState<{ [userId: string]: userPermission }>({});

  // Fetch files and users on page load
  useEffect(() => {
    async function fetchFiles() {
      try {
        const filesData = await getAllFiles();
        setFiles(filesData);

        // For demo, fetch users here
        const allUsers: user[] = [
          { userId: "1", name: "Alice" },
          { userId: "2", name: "Bob" },
          { userId: "3", name: "Charlie" },
        ];
        setUsers(allUsers);

        // Initialize permissions default
        const initialPermissions: { [userId: string]: userPermission } = {};
        allUsers.forEach(u => {
          initialPermissions[u.userId] = { userId: u.userId, canWrite: false, canRead: false };
        });
        setPermissions(initialPermissions);

      } catch (err) {
        console.error("Failed to fetch files:", err);
      }
    }

    fetchFiles();
  }, []);

  const filteredUsers = users.filter(u => u.name.toLowerCase().includes(searchTerm.toLowerCase()));

  const handlePermissionChange = (userId: string, field: "canRead" | "canWrite") => {
    setPermissions(prev => ({
      ...prev,
      [userId]: { ...prev[userId], [field]: !prev[userId][field] }
    }));
  };

  const handleCreateFile = async () => {
    const permsArray = Object.values(permissions);
    try {
      await createFile(newFilename, permsArray);
      setShowModal(false);
      setNewFilename("");
      setSearchTerm("");
      // refetch files
      const filesData = await getAllFiles();
      setFiles(filesData);
    } catch (err) {
      console.error("Failed to create file:", err);
    }
  };

  return (
    <div style={{ padding: "16px" }}>
      <h1>File Manager</h1>
      <button onClick={() => setShowModal(true)}>New File</button>

      {/* Modal */}
      {showModal && (
        <div style={{
          position: "fixed",
          top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.5)",
          display: "flex",
          justifyContent: "center",
          alignItems: "center"
        }}>
          <div style={{ background: "#2b2b2b", padding: "24px", borderRadius: "8px", width: "400px" }}>
            <h2>Create New File</h2>
            <input
              type="text"
              placeholder="Filename"
              value={newFilename}
              onChange={(e) => setNewFilename(e.target.value)}
              style={{ width: "100%", marginBottom: "12px" }}
            />
            <input
              type="text"
              placeholder="Search users..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ width: "100%", marginBottom: "12px" }}
            />
            <div style={{ maxHeight: "200px", overflowY: "auto", marginBottom: "12px" }}>
              {filteredUsers.map(u => (
                <div key={u.userId} style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span>{u.name}</span>
                  <span>
                  <label>
                    <input
                      type="checkbox"
                      checked={permissions[u.userId]?.canRead}
                      onChange={() => handlePermissionChange(u.userId, "canRead")}
                    /> Read
                  </label>

                  <label>
                    <input
                      type="checkbox"
                      checked={permissions[u.userId]?.canWrite}
                      onChange={() => handlePermissionChange(u.userId, "canWrite")}
                    /> Write
                  </label>
                  </span>
                </div>
              ))}
            </div>
            <div style={{ textAlign: "right" }}>
              <button onClick={() => setShowModal(false)} style={{ marginRight: "8px" }}>Cancel</button>
              <button onClick={handleCreateFile}>Create</button>
            </div>
          </div>
        </div>
      )}

      <div style={{ marginTop: "16px" }}>
        {files.length === 0 && <p>No files found.</p>}
        <ul>
          {files.map((file) => (
            <li key={file.fileId} style={{ marginBottom: "8px" }}>
              <span
                style={{ cursor: "pointer", textDecoration: "underline" }}
                onDoubleClick={() => console.log("View file", file.fileId)}
              >
                <a href={`/file/${file.fileId}`}>{file.filename} ({file.size} bytes)</a>
              </span>{" "}
              <button onClick={() => console.log("Rename file", file.fileId)}>Rename</button>{" "}
              <button onClick={() => console.log("Delete file", file.fileId)}>Delete</button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default FileManager;
