import { loader } from '@monaco-editor/react';
import * as monaco from 'monaco-editor';

/**
 * Monaco bootstrap.
 *
 * Two decisions are encoded here, both deliberate:
 *
 * 1. **Self-hosted, not the CDN.** `@monaco-editor/react` loads Monaco from a CDN by
 *    default. In a product whose entire job is reporting third-party supply-chain
 *    risk, fetching a script from a third-party origin at runtime would be
 *    self-contradicting: a CDN compromise would execute code inside a customer's
 *    authenticated dashboard, and it would force a `script-src`/`worker-src`
 *    exception in our CSP. `loader.config({ monaco })` binds the wrapper to the copy
 *    we bundle and version ourselves.
 *
 * 2. **Workers are wired for webpack 5.** Monaco offloads language services to web
 *    workers. `new Worker(new URL(..., import.meta.url))` is the form webpack 5
 *    understands natively, so no `monaco-editor-webpack-plugin` and no custom
 *    `webpack()` block in `next.config.mjs` are needed.
 *
 * Bundle cost: importing `monaco-editor` wholesale pulls in every language. That is
 * several MB, and acceptable for an internal security dashboard — but if it becomes
 * a problem the fix is to import `monaco-editor/esm/vs/editor/editor.api` plus only
 * the `basic-languages` you need, and drop the language workers below.
 */

let configured = false;

/** Registers the bundled Monaco instance and its web workers. Safe to call repeatedly. */
export function setupMonaco(): void {
  if (configured || typeof window === 'undefined') return;
  configured = true;

  loader.config({ monaco });

  window.MonacoEnvironment = {
    getWorker(_workerId: string, label: string): Worker {
      switch (label) {
        case 'json':
          return new Worker(
            new URL('monaco-editor/esm/vs/language/json/json.worker.js', import.meta.url),
            { type: 'module' },
          );
        case 'css':
        case 'scss':
        case 'less':
          return new Worker(
            new URL('monaco-editor/esm/vs/language/css/css.worker.js', import.meta.url),
            { type: 'module' },
          );
        case 'html':
        case 'handlebars':
        case 'razor':
          return new Worker(
            new URL('monaco-editor/esm/vs/language/html/html.worker.js', import.meta.url),
            { type: 'module' },
          );
        case 'typescript':
        case 'javascript':
          return new Worker(
            new URL('monaco-editor/esm/vs/language/typescript/ts.worker.js', import.meta.url),
            { type: 'module' },
          );
        default:
          return new Worker(
            new URL('monaco-editor/esm/vs/editor/editor.worker.js', import.meta.url),
            { type: 'module' },
          );
      }
    },
  };
}

/**
 * Normalises a language id before it reaches Monaco.
 *
 * Language ids come from scanner output, so they are attacker-influenced. Monaco
 * falls back to plain text for an unknown id, but a value containing markup would
 * still end up as a DOM attribute, so it is constrained to the real id alphabet.
 */
export function sanitizeLanguage(language: string): string {
  const cleaned = language.trim().toLowerCase();
  if (!/^[a-z0-9+#._-]{1,32}$/.test(cleaned)) return 'plaintext';
  return cleaned;
}

export { monaco };