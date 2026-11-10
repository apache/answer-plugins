/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const ts = require('typescript');
const { JSDOM } = require('jsdom');
const React = require('react');
const { createRoot } = require('react-dom/client');
const { act } = require('react-dom/test-utils');

const dom = new JSDOM('<!doctype html><body></body>');
Object.assign(global, {
  window: dom.window, document: dom.window.document,
  HTMLElement: dom.window.HTMLElement, Node: dom.window.Node,
  IS_REACT_ACT_ENVIRONMENT: true,
});
let callbacks = 0;
let cutoff = false;
global.MutationObserver = class extends dom.window.MutationObserver {
  constructor(callback) {
    super((...args) => {
      // A regression must fail quickly, rather than hang the test process.
      if (++callbacks > 20) {
        cutoff = true;
        this.disconnect();
        return;
      }
      callback(...args);
    });
  }
};

// Transpile the real hook. Node needs the published CJS entry for KaTeX's
// browser-oriented extensionless import; the implementation/version is unchanged.
const source = path.resolve(__dirname, '../hooks.ts');
const hookModule = new Module(source, module);
hookModule.filename = source;
hookModule.paths = module.paths;
const originalRequire = hookModule.require.bind(hookModule);
hookModule.require = (id) => originalRequire(
  id === 'katex/contrib/auto-render/auto-render'
    ? 'katex/dist/contrib/auto-render.js' : id,
);
hookModule._compile(ts.transpileModule(fs.readFileSync(source, 'utf8'), {
  compilerOptions: { esModuleInterop: true, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText, source);
const { useRenderFormula } = hookModule.exports;
const settle = () => act(() => new Promise((resolve) => setTimeout(resolve, 10)));

async function mount(element, strict = false) {
  callbacks = 0;
  cutoff = false;
  const host = document.createElement('div');
  document.body.append(host);
  const root = createRoot(host);
  function App({ target }) { useRenderFormula(target); return null; }
  const view = (target) => strict
    ? React.createElement(React.StrictMode, null, React.createElement(App, { target }))
    : React.createElement(App, { target });
  await act(() => root.render(view(element)));
  return {
    update: (target) => act(() => root.render(view(target))),
    unmount: async () => { await act(() => root.unmount()); host.remove(); },
  };
}

for (const input of ['$ $$', '$$ $', '$$', '$', '\\(', 'text $$x$$ tail', '\\(x\\)']) {
  test(`settles after rendering ${JSON.stringify(input)} and continues observing`, async () => {
    const target = document.createElement('div');
    const app = await mount(target);
    target.textContent = input;
    await settle();
    assert.equal(cutoff, false);
    assert.equal(callbacks, 1, 'KaTeX writes must not schedule another callback');
    assert.equal(target.querySelectorAll('.katex').length,
      input === 'text $$x$$ tail' || input === '\\(x\\)' ? 1 : 0);
    target.textContent = '\\(y+1\\)';
    await settle();
    assert.equal(callbacks, 2, 'later user edits must still be rendered');
    assert.equal(target.querySelectorAll('.katex').length, 1);
    await app.unmount();
  });
}

test('observes characterData, disconnects on replacement and on unmount', async () => {
  const first = document.createElement('div');
  const text = document.createTextNode('plain');
  first.append(text);
  const app = await mount(first);
  text.data = '\\(a\\)';
  await settle();
  assert.equal(first.querySelectorAll('.katex').length, 1);
  const second = document.createElement('div');
  second.textContent = '$$b$$';
  await app.update(second);
  assert.equal(second.querySelectorAll('.katex').length, 1);
  const count = callbacks;
  first.textContent = '$$old$$';
  await settle();
  assert.equal(callbacks, count, 'old target must be disconnected');
  await app.unmount();
  second.textContent = '$$after$$';
  await settle();
  assert.equal(callbacks, count, 'unmounted target must be disconnected');
});

test('null elements and empty refs are safe; ref reads after DOM commit in StrictMode', async () => {
  const app = await mount(null);
  await app.update({ current: null });
  await app.unmount();
  const host = document.createElement('div');
  document.body.append(host);
  const root = createRoot(host);
  function Formula() {
    const ref = React.useRef(null);
    useRenderFormula(ref);
    return React.createElement('article', { ref }, '$$x$$');
  }
  await act(() => root.render(React.createElement(React.StrictMode, null, React.createElement(Formula))));
  assert.equal(host.querySelectorAll('.katex').length, 1);
  await act(() => root.unmount());
  host.remove();
});
