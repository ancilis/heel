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
    return serverWorker && ts.isCallExpression(node.parent) && node.parent.expression === node
      && (
        ["env.ASSETS.fetch", "handler.fetch"].includes(expression)
        || reviewedControlPlaneFetchCall(node.parent)
      );
  }

  function allowedFetchCall(node) {
    const expression = node.expression.getText(parsed);
    if (serverWorker && ["env.ASSETS.fetch", "handler.fetch"].includes(expression)) return true;
    if (reviewedControlPlaneFetchCall(node)) return true;
    return engineWorker && expression === "fetcher" && isReviewedFetcherCall(node);
  }

  function validateControlPlaneProxyContract() {
    const sourceText = parsed.getFullText();
    if (!serverWorker || !sourceText.includes("CONTROL_PLANE")) return;
    const routeContract = `function controlPlaneRoute(method: string, pathname: string): string | null {
  if (pathname !== CONTROL_PLANE_PREFIX && !pathname.startsWith(\`\${CONTROL_PLANE_PREFIX}/\`)) {
    return null;
  }
  const upstreamPath = pathname.slice(CONTROL_PLANE_PREFIX.length);
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
      'const CONTROL_PLANE_ORIGIN = "https://heel-control-plane.internal";',
      'const WORKSPACE_REF = "ws_[0-9a-f]{16}";',
      'const PROJECT_REF = "prj_[0-9a-f]{32}";',
      'const SYNCED_REVIEW_REF = "synrev_[0-9a-f]{32}";',
      "const upstreamUrl = new URL(upstreamPath, CONTROL_PLANE_ORIGIN);",
      "headers: requestContract.headers,",
      'redirect: "manual",',
      "request.body!.pipeThrough(new FixedLengthStream(requestContract.contentLength))",
      "if (response.status >= 300 && response.status <= 399)",
      'if (requestUrl.search !== "") return proxyError(400, "invalid control plane request", csp);',
      'if (upstreamPath === "") return proxyError(404, "not found", csp);',
      "return proxyControlPlane(request, env, csp, upstreamPath);",
    ]) {
      if (sourceText.split(fragment).length - 1 !== 1) {
        report(parsed, `control-plane proxy is missing exact ${fragment}`);
      }
    }
    if (sourceText.split("const headers = new Headers();").length - 1 !== 2) {
      report(parsed, "control-plane request/response header allowlists are not the reviewed exact contract");
    }
    if (
      sourceText.split(
        'for (const name of ["Content-Type", "Content-Length", "Retry-After"])',
      ).length - 1 !== 1
    ) {
      report(parsed, "control-plane response header allowlist is not the reviewed exact contract");
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
    if (["entries", "freeze", "fromEntries", "is", "keys"].includes(name ?? "")) return true;
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
    if (
      relativeName === "lib/local-reviews.ts"
      && node.text === "globalThis"
      && (ts.isPropertyAccessExpression(node.parent) || ts.isElementAccessExpression(node.parent))
      && node.parent.expression === node
      && memberName(node.parent) === "indexedDB"
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
    if (ts.isIdentifier(node) && isCapabilityIdentifierReference(node)) {
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
      if (root === "globalThis" && name === "indexedDB" && relativeName !== "lib/local-reviews.ts") {
        report(node, "IndexedDB capability outside the result-only store");
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
        "const upstreamUrl = new URL(upstreamPath, CONTROL_PLANE_ORIGIN);",
        "const upstreamUrl = new URL(upstreamPath + new URL(request.url).search, CONTROL_PLANE_ORIGIN);",
      ),
      violation: "missing exact const upstreamUrl",
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
        "function controlPlaneResponse(response: Response, csp: string): Response {\n  const headers = new Headers();",
        "function controlPlaneResponse(response: Response, csp: string): Response {\n  const headers = new Headers(response.headers);",
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
