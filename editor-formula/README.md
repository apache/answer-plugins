# formula plugin
This plugin is used to extend the toolbar of the markdown editor of the answer project.
It provides a toolbar button to insert a formula into the markdown editor.

## Regression tests

After installing the locked dependencies with pnpm 8, run:

```sh
node --test tests/hooks.test.cjs
```

The tests execute the real hook with React, jsdom, and the locked KaTeX version.
They cover incomplete/mixed delimiters, subsequent edits, text-node updates,
ref initialization, StrictMode, target replacement, and observer cleanup. A
callback limit makes a self-triggering observer fail instead of hanging Node.
