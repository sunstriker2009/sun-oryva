import Link from "next/link";
export default function AccessDenied() {
  return <section className="panel"><h1>Access denied</h1><p>Your account is not authorized to access this resource.</p><Link href="/">Return to overview</Link></section>;
}
