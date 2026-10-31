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

await VerifyRoleMappingTransportAsync();

static async Task VerifyRoleMappingTransportAsync()
{
    var calls = new List<string>();
    var handler = new StubHandler(async request =>
    {
        calls.Add(request.Method + " " + request.RequestUri!.AbsolutePath);
        var path = request.RequestUri.AbsolutePath;
        if (path.EndsWith("/protocol/openid-connect/token", StringComparison.Ordinal))
            return Json("""{"access_token":"test-token"}""");
        if (path.EndsWith("/roles/master", StringComparison.Ordinal))
            return Json("""{"id":"role-123","name":"master"}""");
        if (path.EndsWith("/users/subject-a/role-mappings/realm", StringComparison.Ordinal))
        {
            if (request.Method != HttpMethod.Post ||
                request.Headers.Authorization?.Scheme != "Bearer" ||
                request.Headers.Authorization.Parameter != "test-token")
                throw new Exception("Missing authorized role mapping POST.");
            var body = await request.Content!.ReadAsStringAsync();
            if (!body.Contains(""" "role-123" """.Trim()) || !body.Contains(""" "master" """.Trim()))
                throw new Exception("Invalid role representation.");
            return new System.Net.Http.HttpResponseMessage(System.Net.HttpStatusCode.NoContent);
        }
        throw new Exception("Unexpected request " + request.RequestUri);
    });
    using var http = new HttpClient(handler);
    var client = new KeycloakManagementClient(http, new KeycloakManagementOptions
    {
        BaseAddress = new Uri("https://keycloak.example/"),
        Realm = "oryva",
        ClientId = "bootstrap",
        ClientSecret = "test-secret"
    });
    await client.AddMasterRoleMappingAsync("subject-a");
    if (calls.Count != 3 || !calls[2].Contains("/users/subject-a/role-mappings/realm"))
        throw new Exception("Unexpected role mapping call sequence.");
    Console.WriteLine("PASS Keycloak role mapping transport");
}

static System.Net.Http.HttpResponseMessage Json(string value) =>
    new(System.Net.HttpStatusCode.OK)
    {
        Content = new StringContent(value, System.Text.Encoding.UTF8, "application/json")
    };

sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handle)
    : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken) => handle(request);
}
