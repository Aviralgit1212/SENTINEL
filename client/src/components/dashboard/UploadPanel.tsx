import { useRef, useState } from 'react'
import type { DragEvent } from 'react'

import './UploadPanel.css'

interface Props {
  onSelected: (file: File) => void
}

export default function UploadPanel({ onSelected }: Props) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  function handleDrop(event: DragEvent<HTMLElement>) {
    event.preventDefault()
    setDragging(false)

    const file = event.dataTransfer.files[0]
    if (file) onSelected(file)
  }

  function handleDragLeave(event: DragEvent<HTMLElement>) {
    // Ignore leave events fired when moving over child elements.
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
      setDragging(false)
    }
  }

  return (
    <section
      className="upload"
      data-dragging={dragging}
      aria-labelledby="upload-title"
      onDragOver={(event) => {
        event.preventDefault()
        setDragging(true)
      }}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <div>
        <h2 id="upload-title">Drop a file here</h2>
        <p>or choose one from your device. PDF, DOCX, PNG and JPG are supported.</p>
      </div>

      <input
        ref={inputRef}
        type="file"
        accept=".pdf,.docx,.png,.jpg,.jpeg"
        hidden
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) onSelected(file)
          event.target.value = ''
        }}
      />

      <button
        type="button"
        className="btn btn-primary btn-lg"
        onClick={() => inputRef.current?.click()}
      >
        Choose file
      </button>

      <p className="upload-note">
        Files are analyzed locally for type mismatches,
        fingerprints, and available security signals.
      </p>
    </section>
  )
}
