import Link from "next/link";

export default function HomePage() {
  return (
    <>
      <p className="eyebrow">Security administration</p>
      <h1>One identity foundation. Built for trust.</h1>
      <p>ORYVA provides a reusable foundation for identity, authorization and administration.</p>
      <section className="panel" aria-labelledby="access-heading">
        <h2 id="access-heading">Console access</h2>
        <p className="status" role="status">Authentication integration pending</p>
        <p>Administrative functions are unavailable until a validated server-side OIDC session is configured. No account can be activated or managed from this preview.</p>
        <p><Link href="/status">View integration status</Link></p>
      </section>
    </>
  );
}
