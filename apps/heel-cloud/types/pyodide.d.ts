// SPDX-License-Identifier: LicenseRef-Heel-Commercial

export interface PyodideCallable {
  (source: string, answersJson: string): unknown;
  destroy?(): void;
}

export interface PyodideGlobals {
  get(name: string): unknown;
  set(name: string, value: unknown): void;
  delete(name: string): boolean;
}

export interface HeelPyodideRuntime {
  globals: PyodideGlobals;
  loadPackage(packages: string | string[]): Promise<void>;
  loadPackagesFromImports(source: string): Promise<void>;
  runPython(source: string): unknown;
  unpackArchive(
    archive: Uint8Array,
    format: "wheel",
    options: { extractDir: string },
  ): void;
}

export interface PyodideModule {
  version: string;
  loadPyodide(options: {
    cdnUrl: string;
    indexURL: string;
    lockFileURL: string;
    packageBaseUrl: string;
  }): Promise<HeelPyodideRuntime>;
}
