/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { useState } from 'react';
import { Check, Copy, Download, FileCode2, ShieldCheck } from 'lucide-react';

const PATCH_FILENAME = 'bke-worker-f1-completion.patch';
const PATCH_URL = `/${PATCH_FILENAME}`;
const PATCH_SHA256 = 'a1033d891a98c25f3cab7e2f7651f6249f986c5a38ed6c8904b16ab8c8ce1988';
const BASE_COMMIT_SHA = 'a7713c8a5278d6dcb90465b7c5ca8c63ad013e07';

export default function App() {
  const [downloading, setDownloading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleDownloadPatch() {
    setError(null);
    setDownloading(true);
    try {
      const response = await fetch(PATCH_URL, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const blob = await response.blob();
      const patchBlob = new Blob([blob], { type: 'text/x-patch;charset=utf-8' });
      const objectUrl = URL.createObjectURL(patchBlob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = PATCH_FILENAME;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Download failed');
    } finally {
      setDownloading(false);
    }
  }

  async function handleCopyPatch() {
    setError(null);
    try {
      const response = await fetch(PATCH_URL, { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const text = await response.text();
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Clipboard copy failed');
    }
  }

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6 font-sans">
      <section className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-6">
          <div>
            <p className="text-xs font-mono uppercase tracking-widest text-teal-400">
              BKE Worker · FORGE F1 Desktop MVP
            </p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white">
              Exportable Unified Git Patch
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Clean unified diff from <code className="text-slate-200">HEAD</code> with all 39
              changed and added source, test, documentation, and operator certification files.
            </p>
          </div>
          <FileCode2 className="h-8 w-8 shrink-0 text-teal-400" aria-hidden="true" />
        </div>

        <dl className="mt-6 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <dt className="text-slate-400">Patch Filename</dt>
            <dd className="mt-1 font-mono text-slate-100">{PATCH_FILENAME}</dd>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <dt className="text-slate-400">Payload Size</dt>
            <dd className="mt-1 font-mono text-slate-100">434,443 bytes · 39 files (+10,590 / -29)</dd>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 sm:col-span-2">
            <dt className="text-slate-400">Base Commit SHA</dt>
            <dd className="mt-1 font-mono break-all text-slate-100">{BASE_COMMIT_SHA}</dd>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 sm:col-span-2">
            <dt className="flex items-center gap-1.5 text-slate-400">
              <ShieldCheck className="h-3.5 w-3.5 text-teal-400" aria-hidden="true" />
              SHA-256 Checksum
            </dt>
            <dd className="mt-1 font-mono break-all text-teal-300">{PATCH_SHA256}</dd>
          </div>
        </dl>

        <div className="mt-6 flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleDownloadPatch}
            disabled={downloading}
            className="inline-flex items-center gap-2 rounded-lg bg-teal-500 px-4 py-2.5 text-sm font-medium text-slate-950 transition hover:bg-teal-400 disabled:opacity-60 cursor-pointer"
          >
            <Download className="h-4 w-4" aria-hidden="true" />
            {downloading ? 'Preparing download...' : 'Download .patch Attachment'}
          </button>

          <a
            href={PATCH_URL}
            download={PATCH_FILENAME}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:bg-slate-800"
          >
            Direct File Link
          </a>

          <button
            type="button"
            onClick={handleCopyPatch}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800 cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="h-4 w-4 text-teal-400" aria-hidden="true" />
                Copied Patch
              </>
            ) : (
              <>
                <Copy className="h-4 w-4" aria-hidden="true" />
                Copy Raw Patch
              </>
            )}
          </button>
        </div>

        {error && (
          <p role="alert" className="mt-4 rounded-lg border border-red-900 bg-red-950/60 px-3 py-2 text-xs text-red-300">
            {error}
          </p>
        )}

        <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950/80 p-4">
          <p className="text-xs font-medium text-slate-300">Apply Locally & Verify</p>
          <pre className="mt-2 overflow-x-auto font-mono text-xs leading-relaxed text-slate-400">
{`git checkout ${BASE_COMMIT_SHA}
git apply --check ${PATCH_FILENAME}
git apply ${PATCH_FILENAME}
bash scripts/certify-forge-f1-desktop-mvp.sh --dry-run`}
          </pre>
        </div>
      </section>
    </main>
  );
}
