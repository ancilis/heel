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
    if (ts.isFunctionDeclaration(current) && current.name) return current.name.text;
    current = current.parent;
  }
  return null;
}


function containsSensitiveInput(node) {
  let found = false;
  function visit(current) {
    if (ts.isIdentifier(current) && /^(?:source|rawSource|answers|answersJson|answers_json)$/.test(current.text)) {
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
  const networkCapabilities = new Set(["fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon"]);
  const ambientRoots = new Set(["globalThis", "window", "self", "navigator"]);
  const sinkAliases = new Set();
  const engineWorker = relativeName === "workers/heel-review.worker.ts";
  const serverWorker = relativeName === "worker/index.ts";

  function report(node, message) {
    const location = parsed.getLineAndCharacterOfPosition(node.getStart(parsed));
    violations.push(`${relativeName}:${location.line + 1}:${location.character + 1}: ${message}`);
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
        && capture.parent !== undefined
        && ts.isVariableDeclaration(capture.parent)
        && ts.isIdentifier(capture.parent.name)
        && capture.parent.name.text === "bootstrapFetch";
    }
    return serverWorker
      && ["env.ASSETS.fetch", "handler.fetch"].includes(expression)
      && ts.isCallExpression(node.parent)
      && node.parent.expression === node;
  }

  function allowedFetchCall(node) {
    const expression = node.expression.getText(parsed);
    if (serverWorker && ["env.ASSETS.fetch", "handler.fetch"].includes(expression)) return true;
    return engineWorker
      && expression === "fetcher"
      && enclosingFunctionName(node) === "fetchLocal"
      && node.arguments.length >= 1
      && ts.isIdentifier(node.arguments[0])
      && node.arguments[0].text === "path";
  }

  function capabilitySource(node) {
    if (ts.isIdentifier(node)) {
      if (networkCapabilities.has(node.text) || sinkAliases.has(node.text)) return node.text;
      return null;
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = memberName(node);
      if (networkCapabilities.has(name ?? "") && !allowedFetchReference(node)) return name;
    }
    return null;
  }

  function bindingPropertyName(element) {
    const property = element.propertyName ?? element.name;
    if (ts.isComputedPropertyName(property)) return constantString(property.expression);
    return ts.isIdentifier(property) || ts.isStringLiteralLike(property) ? property.text : null;
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
      const value = constantString(current);
      if (value !== null && networkCapabilities.has(value)) {
        found = value;
        return;
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

    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (ts.isIdentifier(node.name)) {
        recordAlias(node.name, node.initializer, node);
      } else if (
        ts.isObjectBindingPattern(node.name)
        && ambientRoots.has(rootName(node.initializer) ?? "")
      ) {
        for (const element of node.name.elements) {
          if (
            ts.isIdentifier(element.name)
            && networkCapabilities.has(bindingPropertyName(element) ?? "")
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
      const root = rootName(node);
      const reflectiveAuthority = reflectiveMethodAuthority(node);
      if (reflectiveAuthority !== null) {
        report(node, `reflective method authority reference ${reflectiveAuthority}`);
      }
      if (networkCapabilities.has(name ?? "") && !allowedFetchReference(node)) {
        report(node, `network sink capability reference ${name}`);
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
      const root = rootName(node.expression);
      const args = [...(node.arguments ?? [])];
      if (ts.isCallExpression(node)) {
        const reflected = reflectiveNetworkLookup(node);
        if (reflected !== null) report(node, `reflective network capability lookup ${reflected}`);
      }
      if (ts.isIdentifier(node.expression) && sinkAliases.has(node.expression.text)) {
        report(node, `network sink alias ${node.expression.text}`);
      }
      if (networkCapabilities.has(name ?? "") && !allowedFetchCall(node)) {
        report(node, `network sink ${name}`);
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
          || relativeName === "workers/heel-review.worker.ts";
        if (!allowed) report(node, "customer input crosses an unapproved message boundary");
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(parsed);
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


test("the privacy analyzer permits only the reviewed engine and server fetch sites", () => {
  const engine = `
const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
const bootstrapFetch = scope.fetch.bind(scope);
async function fetchLocal(fetcher, path) { return fetcher(path); }
function send(value) { scope.postMessage(JSON.stringify(value)); }
function guardProperty(owner, name) {
  Object.defineProperty(owner, name, {value: () => { throw new Error("disabled"); }});
}
function guardAmbientNetwork() {
  const ambient = scope as unknown as Record<string, unknown>;
  for (const name of ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"]) {
    guardProperty(ambient, name);
  }
}
scope.onmessage = () => {};
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
