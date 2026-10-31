using Sun.Security.Bootstrap;

var marker = MasterIdentityOwnership.ComputeMarker("deployment-test");
KeycloakUser Candidate(string id = "subject-a", bool enabled = false,
    string? owner = null, string username = "master") =>
    new(id, username, enabled, new Dictionary<string, List<string>>
    {
        [MasterIdentityOwnership.AttributeName] = [owner ?? marker]
    });
var pending = new MasterReservation("pending", null);
var cases = new (string Name, MasterReservation Reservation, KeycloakUser? Candidate,
    KeycloakUser[] Members, MasterRoleAssignmentDecision Expected)[]
{
    ("eligible", pending, Candidate(), [], MasterRoleAssignmentDecision.Eligible),
    ("same subject recovery", pending, Candidate(), [Candidate()], MasterRoleAssignmentDecision.AlreadyAssigned),
    ("different member", pending, Candidate(), [Candidate("other")], MasterRoleAssignmentDecision.Reject),
    ("multiple members", pending, Candidate(), [Candidate(), Candidate("other")], MasterRoleAssignmentDecision.Reject),
    ("enabled candidate", pending, Candidate(enabled: true), [], MasterRoleAssignmentDecision.Reject),
    ("mismatched owner", pending, Candidate(owner: "wrong"), [], MasterRoleAssignmentDecision.Reject),
    ("wrong username", pending, Candidate(username: "other"), [], MasterRoleAssignmentDecision.Reject),
    ("missing candidate", pending, null, [], MasterRoleAssignmentDecision.Reject),
    ("active reservation", new MasterReservation("active", "subject-a"), Candidate(), [], MasterRoleAssignmentDecision.Reject),
    ("pending bound subject", new MasterReservation("pending", "subject-a"), Candidate(), [], MasterRoleAssignmentDecision.Reject),
    ("enabled existing role member", pending, Candidate(), [Candidate(enabled: true)], MasterRoleAssignmentDecision.Reject)
};
foreach (var test in cases)
{
    var actual = MasterRoleAssignmentPolicy.Evaluate(
        test.Reservation, test.Candidate, "master", marker, test.Members);
    if (actual != test.Expected)
        throw new Exception($"{test.Name}: expected {test.Expected}, got {actual}");
    Console.WriteLine($"PASS {test.Name}");
}
Console.WriteLine($"Passed {cases.Length} policy cases.");
