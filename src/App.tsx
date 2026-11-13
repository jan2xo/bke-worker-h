/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
import { Lock, ShieldCheck } from 'lucide-react';

export default function App() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6 font-sans">
      <section className="w-full max-w-2xl rounded-xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-6">
          <div>
            <p className="text-xs font-mono uppercase tracking-widest text-teal-400">
              BKE Worker · FORGE F1 Desktop MVP
            </p>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white">
              Desktop Controller &amp; MV3 Bridge Workspace
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              Sandbox source workspace for the BKE Desktop Worker MV3 extension, native messaging
              host, loopback controller daemon, GitHub authority harness, and packaging scripts.
            </p>
          </div>
          <ShieldCheck className="h-8 w-8 shrink-0 text-teal-400" aria-hidden="true" />
        </div>

        <dl className="mt-6 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <dt className="text-slate-400">Live ChatGPT Send Default</dt>
            <dd className="mt-1 flex items-center gap-1.5 font-mono text-amber-300">
              <Lock className="h-3.5 w-3.5" aria-hidden="true" />
              LOCKED FALSE
            </dd>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <dt className="text-slate-400">Level 7 Live Browser Acceptance</dt>
            <dd className="mt-1 font-mono text-slate-200">HUMAN_ONLY_GATE</dd>
          </div>
        </dl>

        <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950/80 p-4">
          <p className="text-xs font-medium text-slate-300">Verification Entrypoints</p>
          <pre className="mt-2 overflow-x-auto font-mono text-xs leading-relaxed text-slate-400">
{`npm --prefix bke-worker/browser-extension run check
bash bke-worker/scripts/certify-forge-f1-desktop-mvp.sh --sandbox --dry-run
bash bke-worker/scripts/package-desktop-worker.sh package`}
          </pre>
        </div>
      </section>
    </main>
  );
}
