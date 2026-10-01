import type { Metadata } from 'next';
import Link from 'next/link';

import './globals.css';

export const metadata: Metadata = {
  title: 'Syscanner',
  description: 'SAST, secrets detection and dependency vulnerability scanning.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="border-b border-slate-800 bg-panel/60 backdrop-blur">
          <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
            <Link href="/" className="text-lg font-semibold tracking-tight text-white">
              Syscanner
            </Link>
            <nav className="flex gap-6 text-sm text-slate-400">
              <Link href="/" className="hover:text-slate-200">
                Overview
              </Link>
              <Link href="/repositories" className="hover:text-slate-200">
                Repositories
              </Link>
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
