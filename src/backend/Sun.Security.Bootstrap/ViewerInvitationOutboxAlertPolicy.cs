namespace Sun.Security.Bootstrap;

/// <summary>
/// Internal, side-effect-free interpretation of aggregate invitation outbox counters.
/// This is not an alert publisher, SMTP health probe, or authorization decision.
/// Thresholds must be supplied by an operator; there are no production defaults.
/// </summary>
public static class ViewerInvitationOutboxAlertPolicy
{
    private static readonly TimeSpan FutureClockSkewAllowance = TimeSpan.FromSeconds(30);

    public static ViewerInvitationOutboxAlertEvaluation Evaluate(
        ViewerInvitationOutboxHealthSnapshot snapshot,
        ViewerInvitationOutboxAlertThresholds thresholds,
        DateTime observedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(thresholds);
        thresholds.Validate();

        if (observedAtUtc.Kind != DateTimeKind.Utc ||
            snapshot.CapturedAtUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("Monitoring timestamps must be UTC.");

        if (snapshot.Pending < 0 || snapshot.DuePending < 0 ||
            snapshot.Leased < 0 || snapshot.ExpiredLeases < 0 ||
            snapshot.RetryPending < 0 || snapshot.ExhaustedUnsent < 0 ||
            snapshot.RelayAccepted < 0 || snapshot.Cancelled < 0 ||
            snapshot.DuePending > snapshot.Pending ||
            snapshot.RetryPending > snapshot.Pending ||
            snapshot.ExpiredLeases > snapshot.Leased ||
            (snapshot.ExhaustedUnsent > snapshot.Pending &&
             snapshot.ExhaustedUnsent - snapshot.Pending > snapshot.Leased))
            throw new InvalidOperationException("Invitation monitoring snapshot is inconsistent.");

        // A stale or future-dated sample is UNKNOWN, never silently healthy.
        // The 30-second future tolerance only covers minor clock skew.
        var age = observedAtUtc - snapshot.CapturedAtUtc;
        if (age > thresholds.MaximumSnapshotAge || age < -FutureClockSkewAllowance)
            return new(ViewerInvitationOutboxAlertSeverity.Unknown,
                ViewerInvitationOutboxAlertReasons.UntrustedSnapshot);

        var reasons = ViewerInvitationOutboxAlertReasons.None;
        if (snapshot.DuePending >= thresholds.DuePendingWarning)
            reasons |= ViewerInvitationOutboxAlertReasons.DueBacklog;
        if (snapshot.RetryPending >= thresholds.RetryPendingWarning)
            reasons |= ViewerInvitationOutboxAlertReasons.RetryBacklog;
        if (snapshot.ExpiredLeases >= thresholds.ExpiredLeasesCritical)
            reasons |= ViewerInvitationOutboxAlertReasons.ExpiredLeases;
        if (snapshot.ExhaustedUnsent >= thresholds.ExhaustedUnsentCritical)
            reasons |= ViewerInvitationOutboxAlertReasons.ExhaustedUnsent;

        var critical = (reasons & (ViewerInvitationOutboxAlertReasons.ExpiredLeases |
                                   ViewerInvitationOutboxAlertReasons.ExhaustedUnsent)) != 0;
        return new(critical ? ViewerInvitationOutboxAlertSeverity.Critical :
            reasons == ViewerInvitationOutboxAlertReasons.None
                ? ViewerInvitationOutboxAlertSeverity.NoThresholdExceeded
                : ViewerInvitationOutboxAlertSeverity.Warning, reasons);
    }
}

/// <summary>Explicit operator-selected thresholds; zero is never a valid threshold.</summary>
public sealed record ViewerInvitationOutboxAlertThresholds(
    long DuePendingWarning,
    long RetryPendingWarning,
    long ExpiredLeasesCritical,
    long ExhaustedUnsentCritical,
    TimeSpan MaximumSnapshotAge)
{
    public void Validate()
    {
        if (DuePendingWarning <= 0 || RetryPendingWarning <= 0 ||
            ExpiredLeasesCritical <= 0 || ExhaustedUnsentCritical <= 0 ||
            MaximumSnapshotAge <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(ViewerInvitationOutboxAlertThresholds),
                "Monitoring thresholds and maximum snapshot age must be positive.");
    }
}

public enum ViewerInvitationOutboxAlertSeverity
{
    NoThresholdExceeded,
    Warning,
    Critical,
    Unknown
}

[Flags]
public enum ViewerInvitationOutboxAlertReasons
{
    None = 0,
    DueBacklog = 1,
    RetryBacklog = 2,
    ExpiredLeases = 4,
    ExhaustedUnsent = 8,
    UntrustedSnapshot = 16
}

/// <summary>Low-cardinality signal only; contains no recipient, identity or token.</summary>
public sealed record ViewerInvitationOutboxAlertEvaluation(
    ViewerInvitationOutboxAlertSeverity Severity,
    ViewerInvitationOutboxAlertReasons Reasons);
