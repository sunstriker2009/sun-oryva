import { requireServerResource } from "../../lib/guard";
export default async function AuditPage() {
  await requireServerResource("audit");
  return <section className="panel"><h1>Audit events</h1><p>Authorized master or admin required.</p></section>;
}
