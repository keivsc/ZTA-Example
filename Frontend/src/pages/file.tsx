"use client";
import { useEffect, useState, useRef } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getFile, modifyFile } from "../utils/api";
import TipTapEditor from "../components/editor";
import type { TipTapEditorRef } from "../components/editor";
import { navigateTo } from "../utils/navigate";

interface FileItem {
  fileId: string;
  filename: string;
  ownerId: string;
  size: number;
  type: string; // '.txt', '.json', etc.
  content: string; // HEX STRING from backend
}



function getOwner(fileId: string) {
  return "bob";
}

export default function FilePage() {
    const navigator = useNavigate();
    const { id } = useParams();
    const [file, setFile] = useState<FileItem | null>(null);
    const [blobUrl, setBlobUrl] = useState("");
    const [saving, setSaving] = useState(false);
    const editorRef = useRef<TipTapEditorRef>(null)

    async function updateFile(id:string, content:string){
        const updateRes = await modifyFile(id, content);
        if (updateRes.status != 200){
            const updateJson = await updateRes.json();
            return alert("File not saved\n"+updateJson.error);
        }
        setSaving(false);
        return alert("Saved!");
    }

    useEffect(() => {
        (async () => {
        if (!id) return;

        const f = await getFile(id);
        setFile(f);

        const contentHex = f.content || "";
        const blob = contentHex ? hexToBlob(contentHex) : new Blob([]);
        const url = URL.createObjectURL(blob);
        setBlobUrl(url);
        })();
    }, [id]);

    if (!file) return <div>Loading...</div>;

    const ext = file.type?.replace(".", "").toLowerCase();

    const handleSave = async () => {
        if (!editorRef.current) return
        const htmlContent = editorRef.current.getContent()
        setSaving(true);
        await updateFile(file.fileId, htmlContent)
    }

    const navigateBack = ()=>{
        navigateTo(navigator, '/explorer');
    }

    return (
        <div>
        <h1>{file.filename}</h1>
        <p>Owner: {getOwner(file.fileId)}</p>

        {/* TEXT EDITOR */}
        {isTextEditable(file.type) && <TipTapEditor ref={editorRef}  content={file.content}/>}

        {/* IMAGE */}
        {isImageFile(file.type) && <img src={blobUrl} alt={file.filename} className="max-w-full rounded shadow" />}

        {/* PDF */}
        {ext === "pdf" && <embed src={blobUrl} type="application/pdf" width="100%" height="600px" />}

        {/* UNSUPPORTED */}
        {!isTextEditable(file.type) && !isImageFile(file.type) && ext !== "pdf" && (
            <div className="text-red-500 font-semibold">File type not supported.</div>
        )}
        <div style={{ display: "flex", gap: "8px", justifyContent:"center" }}>
            {/* BACK BUTTON */}
            <button onClick={navigateBack} style={{}}>
                Back
            </button>

            {/* SAVE BUTTON */}
            {isTextEditable(file.type) && (
                <button
                disabled={saving}
                onClick={handleSave}
                className="px-4 py-2 bg-blue-600 text-white rounded mt-2"
                >
                {saving ? "Saving..." : "Save"}
                </button>
            )}
        </div>


        </div>
    );
}

/* ───────────── HELPERS ───────────── */
function hexToBlob(hex: string): Blob {
  const len = hex.length / 2;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return new Blob([bytes]);
}

function isTextEditable(type: string | undefined): boolean {
  if (!type) return false;
  const ext = type.replace(".", "").toLowerCase();
  return ["txt", "md", "json", "js", "ts", "html", "css"].includes(ext);
}

function isImageFile(type: string | undefined): boolean {
  if (!type) return false;
  const ext = type.replace(".", "").toLowerCase();
  return ["png", "jpg", "jpeg", "gif", "webp"].includes(ext);
}
