import Link from "next/link";

export default function StatusPage() {
  return (
    <>
      <p className="eyebrow">Integration readiness</p>
      <h1>Secure access is not yet enabled.</h1>
      <section className="panel" aria-labelledby="status-heading">
        <h2 id="status-heading">Authentication status</h2>
        <p role="status">OIDC login/logout and server-side session validation are pending implementation and end-to-end verification.</p>
        <p>Until verified, the console does not expose administration routes, credential entry, enrollment, or recovery.</p>
        <p><Link href="/">Return to console overview</Link></p>
      </section>
    </>
  );
}
