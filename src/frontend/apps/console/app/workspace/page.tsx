import { requireServerResource } from "../../lib/guard";
export default async function WorkspacePage() {
  await requireServerResource("workspace");
  return <section className="panel"><h1>Workspace</h1><p>Authenticated session required.</p></section>;
}
