using System.Text.Json;
using Sun.Security.Bootstrap;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
}

static void Reject<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new Exception("Invalid monitoring configuration or snapshot was accepted.");
}

var now = new DateTime(2026, 11, 2, 18, 0, 0, DateTimeKind.Utc);
var thresholds = new ViewerInvitationOutboxAlertThresholds(
    DuePendingWarning: 3, RetryPendingWarning: 2,
    ExpiredLeasesCritical: 1, ExhaustedUnsentCritical: 2,
    MaximumSnapshotAge: TimeSpan.FromMinutes(2));

ViewerInvitationOutboxHealthSnapshot Sample(
    long pending = 0, long due = 0, long leased = 0,
    long expired = 0, long retry = 0, long exhausted = 0,
    DateTime? captured = null) =>
    new(captured ?? now, pending, due, leased, expired, retry, exhausted, 4, 5);

ViewerInvitationOutboxAlertEvaluation Evaluate(ViewerInvitationOutboxHealthSnapshot snapshot) =>
    ViewerInvitationOutboxAlertPolicy.Evaluate(snapshot, thresholds, now);

Check(Evaluate(Sample()).Severity == ViewerInvitationOutboxAlertSeverity.NoThresholdExceeded,
    "Zero counters must not trigger a configured positive threshold.");
Check(Evaluate(Sample(pending: 2, due: 2, retry: 1)).Severity ==
    ViewerInvitationOutboxAlertSeverity.NoThresholdExceeded,
    "Below-threshold values must not trigger.");
var warning = Evaluate(Sample(pending: 3, due: 3, retry: 2));
Check(warning.Severity == ViewerInvitationOutboxAlertSeverity.Warning &&
      warning.Reasons == (ViewerInvitationOutboxAlertReasons.DueBacklog |
                          ViewerInvitationOutboxAlertReasons.RetryBacklog),
    "Warning boundaries and combined reason flags failed.");
var critical = Evaluate(Sample(pending: 3, due: 3, leased: 2,
    expired: 1, retry: 2, exhausted: 2));
Check(critical.Severity == ViewerInvitationOutboxAlertSeverity.Critical &&
      critical.Reasons.HasFlag(ViewerInvitationOutboxAlertReasons.ExpiredLeases) &&
      critical.Reasons.HasFlag(ViewerInvitationOutboxAlertReasons.ExhaustedUnsent),
    "Critical threshold must override warning.");
Check(Evaluate(Sample(captured: now.AddMinutes(-2))).Severity ==
    ViewerInvitationOutboxAlertSeverity.NoThresholdExceeded,
    "Exact maximum sample age must remain valid.");
Check(Evaluate(Sample(captured: now.AddMinutes(-2).AddTicks(-1))).Severity ==
    ViewerInvitationOutboxAlertSeverity.Unknown,
    "Stale sample must not report a healthy state.");
Check(Evaluate(Sample(captured: now.AddSeconds(31))).Reasons ==
    ViewerInvitationOutboxAlertReasons.UntrustedSnapshot,
    "Excessive future clock skew must be unknown.");
Check(Evaluate(Sample(captured: now.AddSeconds(30))).Severity ==
    ViewerInvitationOutboxAlertSeverity.NoThresholdExceeded,
    "Documented small future clock tolerance must be accepted.");
Reject<ArgumentOutOfRangeException>(() =>
    ViewerInvitationOutboxAlertPolicy.Evaluate(Sample(),
        thresholds with { ExpiredLeasesCritical = 0 }, now));
Reject<ArgumentOutOfRangeException>(() =>
    ViewerInvitationOutboxAlertPolicy.Evaluate(Sample(),
        thresholds with { MaximumSnapshotAge = TimeSpan.Zero }, now));
Reject<ArgumentException>(() =>
    ViewerInvitationOutboxAlertPolicy.Evaluate(Sample(), thresholds,
        DateTime.SpecifyKind(now, DateTimeKind.Unspecified)));
Reject<InvalidOperationException>(() => Evaluate(Sample(pending: 1, due: 2)));
Reject<InvalidOperationException>(() => Evaluate(Sample(leased: 0, expired: 1)));
Reject<InvalidOperationException>(() => Evaluate(Sample(pending: 1, retry: 2)));
Reject<InvalidOperationException>(() => Evaluate(Sample(pending: 1, exhausted: 2)));
Reject<InvalidOperationException>(() => Evaluate(Sample(pending: -1)));
var serialized = JsonSerializer.Serialize(critical);
Check(!serialized.Contains("recipient", StringComparison.OrdinalIgnoreCase) &&
      !serialized.Contains("subject", StringComparison.OrdinalIgnoreCase) &&
      !serialized.Contains("token", StringComparison.OrdinalIgnoreCase) &&
      serialized.Contains("Severity", StringComparison.Ordinal),
    "Alert evaluation must remain aggregate-only.");
Console.WriteLine("PASS invitation outbox alert thresholds, precedence, stale/future clocks, validation and non-disclosure");
