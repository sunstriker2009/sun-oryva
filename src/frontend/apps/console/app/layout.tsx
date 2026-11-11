import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ORYVA by Sun | Security Console",
  description: "Identity. Trust. Protection.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip" href="#main">Skip to main content</a>
        <div className="shell">
          <header className="brand" aria-label="ORYVA by Sun">ORYVA <span>by Sun</span></header>
          <main id="main">{children}</main>
          <footer className="footer">SUN-001 · Identity. Trust. Protection.</footer>
        </div>
      </body>
    </html>
  );
}
