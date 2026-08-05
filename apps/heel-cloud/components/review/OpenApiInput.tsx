// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useRef, useState, type ChangeEvent, type DragEvent, type KeyboardEvent } from "react";
import { MAX_BROWSER_INPUT_BYTES } from "../../lib/browser-review-client";


interface OpenApiInputProps {
  source: string;
  disabled: boolean;
  onSourceChange(source: string): void;
  onError(message: string): void;
  onSubmit(): void;
}


async function readFileBytes(file: File): Promise<ArrayBuffer> {
  if (typeof file.arrayBuffer === "function") return file.arrayBuffer();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) resolve(reader.result);
      else reject(new Error("file did not contain bytes"));
    };
    reader.onerror = () => reject(new Error("file could not be read"));
    reader.readAsArrayBuffer(file);
  });
}


export function OpenApiInput({
  source,
  disabled,
  onSourceChange,
  onError,
  onSubmit,
}: OpenApiInputProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [selectedFile, setSelectedFile] = useState("");
  const bytes = new TextEncoder().encode(source).byteLength;

  async function acceptFile(file: File | undefined): Promise<void> {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".json")) {
      setSelectedFile("");
      onError(`${file.name} is not a .json file. Choose an OpenAPI JSON document.`);
      return;
    }
    if (file.size > MAX_BROWSER_INPUT_BYTES) {
      setSelectedFile("");
      onError(`${file.name} is ${file.size.toLocaleString("en-US")} bytes; Heel's limit is 2 MiB.`);
      return;
    }
    try {
      const contents = await readFileBytes(file);
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(contents);
      onSourceChange(decoded);
      setAcknowledged(false);
      setSelectedFile(`${file.name} · ${file.size.toLocaleString("en-US")} bytes`);
      onError("");
    } catch {
      setSelectedFile("");
      onError("That file is not valid UTF-8 and cannot be reviewed safely.");
    }
  }

  function submit(): void {
    if (
      source.trim().length > 0
      && bytes <= MAX_BROWSER_INPUT_BYTES
      && !acknowledged
    ) {
      onError("Confirm this is an API description, not credentials or customer data, before reviewing.");
      return;
    }
    onSubmit();
  }

  function fileChanged(event: ChangeEvent<HTMLInputElement>): void {
    void acceptFile(event.target.files?.[0]);
    event.target.value = "";
  }

  function dropped(event: DragEvent<HTMLDivElement>): void {
    event.preventDefault();
    void acceptFile(event.dataTransfer.files?.[0]);
  }

  function dropKey(event: KeyboardEvent<HTMLDivElement>): void {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      inputRef.current?.click();
    }
  }

  return (
    <div className="openapi-input">
      <div className="input-heading">
        <div>
          <p className="eyebrow">Your document</p>
          <h3>Paste or choose OpenAPI JSON</h3>
        </div>
        <span className={bytes > MAX_BROWSER_INPUT_BYTES ? "byte-count byte-count-error" : "byte-count"}>
          {bytes.toLocaleString("en-US")} bytes / 2 MiB
        </span>
      </div>
      <label className="sr-only" htmlFor="openapi-source">Paste OpenAPI JSON</label>
      <textarea
        id="openapi-source"
        value={source}
        onChange={(event) => {
          onSourceChange(event.target.value);
          setAcknowledged(false);
          setSelectedFile("");
        }}
        placeholder={'{\n  "openapi": "3.1.0",\n  "paths": { ... }\n}'}
        spellCheck={false}
        disabled={disabled}
      />
      {selectedFile ? <p className="selected-file">Selected locally: {selectedFile}</p> : null}
      <div
        className="drop-zone"
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label="Drop OpenAPI JSON or choose a file"
        aria-disabled={disabled}
        onDragOver={(event) => event.preventDefault()}
        onDrop={disabled ? undefined : dropped}
        onKeyDown={disabled ? undefined : dropKey}
        onClick={disabled ? undefined : () => inputRef.current?.click()}
      >
        <strong>Drop .json here</strong>
        <span>or choose a file from this device</span>
      </div>
      <label className="file-label" htmlFor="openapi-file">Choose OpenAPI JSON file</label>
      <input
        className="sr-only"
        ref={inputRef}
        id="openapi-file"
        type="file"
        accept=".json,application/json"
        onChange={fileChanged}
        disabled={disabled}
      />
      <label className="input-acknowledgement">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
          disabled={disabled}
        />
        <span>
          I confirm this is an API description, not credentials or customer data.
          <small>This acknowledgement stays in memory and is never uploaded.</small>
        </span>
      </label>
      <button className="button button-primary" type="button" onClick={submit} disabled={disabled}>
        Review this OpenAPI
      </button>
    </div>
  );
}
