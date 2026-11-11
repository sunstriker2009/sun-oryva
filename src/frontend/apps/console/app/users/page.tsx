import { requireServerResource } from "../../lib/guard";
export default async function UsersPage() {
  await requireServerResource("users");
  return <section className="panel"><h1>User administration</h1><p>Authorized master or admin required.</p></section>;
}
