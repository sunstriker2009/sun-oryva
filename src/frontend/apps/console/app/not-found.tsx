import Link from "next/link";
export default function NotFound() {
  return <section className="panel"><h1>Page not found</h1><p>The requested page is unavailable.</p><Link href="/">Return to overview</Link></section>;
}
