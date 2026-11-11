import { requireServerResource } from "../../lib/guard";
export default async function SecurityPage() {
  await requireServerResource("security");
  return <section className="panel"><h1>Security settings</h1><p>Authorized master required.</p></section>;
}
