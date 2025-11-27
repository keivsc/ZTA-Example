import '../index.css'
import React, { forwardRef, useImperativeHandle } from 'react'
import type { Editor } from '@tiptap/react'
import { EditorContent, useEditor, useEditorState } from '@tiptap/react'
import StarterKit from '@tiptap/starter-kit'

// ───── Types ─────
type EditorStateType = {
  isBold: boolean
  canBold: boolean
  isItalic: boolean
  canItalic: boolean
  isStrike: boolean
  canStrike: boolean
  isCode: boolean
  canCode: boolean
  canClearMarks: boolean
  isParagraph: boolean
  isHeading1: boolean
  isHeading2: boolean
  isHeading3: boolean
  isHeading4: boolean
  isHeading5: boolean
  isHeading6: boolean
  isBulletList: boolean
  isOrderedList: boolean
  isCodeBlock: boolean
  isBlockquote: boolean
  canUndo: boolean
  canRedo: boolean
}

export type TipTapEditorRef = {
  getContent: () => string
  setContent: (content: string) => void
}


interface TipTapEditorProps {
  content?: string
}

// ───── MenuBar ─────
function MenuBar({ editor }: { editor: Editor }) {
  const editorState = useEditorState<EditorStateType>({
    editor,
    selector: ctx => ({
      isBold: ctx.editor.isActive('bold'),
      canBold: ctx.editor.can().chain().toggleBold().run(),
      isItalic: ctx.editor.isActive('italic'),
      canItalic: ctx.editor.can().chain().toggleItalic().run(),
      isStrike: ctx.editor.isActive('strike'),
      canStrike: ctx.editor.can().chain().toggleStrike().run(),
      isCode: ctx.editor.isActive('code'),
      canCode: ctx.editor.can().chain().toggleCode().run(),
      canClearMarks: ctx.editor.can().chain().unsetAllMarks().run(),
      isParagraph: ctx.editor.isActive('paragraph'),
      isHeading1: ctx.editor.isActive('heading', { level: 1 }),
      isHeading2: ctx.editor.isActive('heading', { level: 2 }),
      isHeading3: ctx.editor.isActive('heading', { level: 3 }),
      isHeading4: ctx.editor.isActive('heading', { level: 4 }),
      isHeading5: ctx.editor.isActive('heading', { level: 5 }),
      isHeading6: ctx.editor.isActive('heading', { level: 6 }),
      isBulletList: ctx.editor.isActive('bulletList'),
      isOrderedList: ctx.editor.isActive('orderedList'),
      isCodeBlock: ctx.editor.isActive('codeBlock'),
      isBlockquote: ctx.editor.isActive('blockquote'),
      canUndo: ctx.editor.can().chain().undo().run(),
      canRedo: ctx.editor.can().chain().redo().run(),
    }),
  })

  const cls = (active: boolean | undefined) => (active ? 'is-active' : undefined)
  const headingLevels: (1 | 2 | 3 | 4 | 5 | 6)[] = [1, 2, 3, 4, 5, 6]

  return (
    <div className="control-group">
      <div className="button-group" style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
        <button onClick={() => editor.chain().focus().toggleBold().run()} disabled={!editorState.canBold} className={cls(editorState.isBold)}>Bold</button>
        <button onClick={() => editor.chain().focus().toggleItalic().run()} disabled={!editorState.canItalic} className={cls(editorState.isItalic)}>Italic</button>
        <button onClick={() => editor.chain().focus().toggleStrike().run()} disabled={!editorState.canStrike} className={cls(editorState.isStrike)}>Strike</button>
        <button onClick={() => editor.chain().focus().toggleCode().run()} disabled={!editorState.canCode} className={cls(editorState.isCode)}>Code</button>
        <button onClick={() => editor.chain().focus().unsetAllMarks().run()}>Clear marks</button>
        <button onClick={() => editor.chain().focus().clearNodes().run()}>Clear nodes</button>
        <button onClick={() => editor.chain().focus().setParagraph().run()} className={cls(editorState.isParagraph)}>Paragraph</button>

        {headingLevels.map(level => (
          <button
            key={level}
            onClick={() => editor.chain().focus().toggleHeading({ level }).run()}
            className={cls(editorState[`isHeading${level}` as keyof EditorStateType])}
          >
            H{level}
          </button>
        ))}

        <button onClick={() => editor.chain().focus().toggleBulletList().run()} className={cls(editorState.isBulletList)}>Bullet list</button>
        <button onClick={() => editor.chain().focus().toggleOrderedList().run()} className={cls(editorState.isOrderedList)}>Ordered list</button>
        <button onClick={() => editor.chain().focus().toggleCodeBlock().run()} className={cls(editorState.isCodeBlock)}>Code block</button>
        <button onClick={() => editor.chain().focus().toggleBlockquote().run()} className={cls(editorState.isBlockquote)}>Blockquote</button>
        <button onClick={() => editor.chain().focus().setHorizontalRule().run()}>Horizontal rule</button>
        <button onClick={() => editor.chain().focus().setHardBreak().run()}>Hard break</button>
        <button onClick={() => editor.chain().focus().undo().run()} disabled={!editorState.canUndo}>Undo</button>
        <button onClick={() => editor.chain().focus().redo().run()} disabled={!editorState.canRedo}>Redo</button>
      </div>
    </div>
  )
}

// ───── TipTapEditor with ref ─────
const TipTapEditor = forwardRef<TipTapEditorRef, TipTapEditorProps>(({ content = '' }, ref) => {
  const editor = useEditor({ extensions: [StarterKit], content })

  useImperativeHandle(ref, () => ({
    getContent: () => editor?.getHTML() || '',
    setContent: (newContent: string) => editor?.commands.setContent(newContent)
  }))

  if (!editor) return null

  return (
    <div>
      <MenuBar editor={editor} />
      <div className="editor-wrapper">
        <EditorContent editor={editor} />
      </div>
    </div>
  )
})

export default TipTapEditor;
