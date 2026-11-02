namespace Sun.Security.Bootstrap;

/// <summary>
/// A single, explicitly invoked internal outbox dispatch iteration. It is not
/// registered as a hosted service and cannot start sending email on deployment.
/// Callers must supply a separately reviewed, trusted transport; the only
/// repository implementation is the loopback-only Mailpit test adapter.
/// </summary>
public sealed class ViewerInvitationDispatchOnce(
    ViewerInvitationOutboxLeaseStore leases,
    ViewerInvitationSmtpHandoff handoff)
{
    /// <summary>
    /// Sweeps invalid invitations, claims at most one eligible delivery, and
    /// attempts one transaction-held SMTP relay handoff. No token or recipient
    /// is included in the result. SMTP relay acceptance is not inbox delivery.
    /// Infrastructure and database failures propagate rather than being
    /// misreported as successful delivery.
    /// </summary>
    public async Task<ViewerInvitationDispatchResult> RunOnceAsync(
        CancellationToken cancellationToken = default)
    {
        await leases.SweepInvalidAsync(cancellationToken);
        var lease = await leases.ClaimNextAsync(cancellationToken);
        if (lease is null)
            return ViewerInvitationDispatchResult.NoEligibleDelivery;

        try
        {
            if (await handoff.TrySendAsync(lease, cancellationToken))
                return ViewerInvitationDispatchResult.RelayAccepted;

            // Eligibility can change after the claim. The handoff itself
            // rechecks the live viewer/challenge/lease under PostgreSQL locks.
            await leases.SweepInvalidAsync(cancellationToken);
            return await leases.ReleaseForRetryAsync(lease, cancellationToken)
                ? ViewerInvitationDispatchResult.Deferred
                : ViewerInvitationDispatchResult.RejectedOrLeaseLost;
        }
        catch (ViewerInvitationTransportException)
        {
            // SMTP failures are ambiguous: the relay may already have
            // accepted DATA. Retry only through the fenced, delayed lease
            // coordinator. Never log or return the original SMTP exception.
            return await leases.ReleaseForRetryAsync(lease, cancellationToken)
                ? ViewerInvitationDispatchResult.TransportRetryScheduled
                : ViewerInvitationDispatchResult.RejectedOrLeaseLost;
        }
    }
}

/// <summary>Non-sensitive outcome of one explicit dispatch attempt.</summary>
public enum ViewerInvitationDispatchResult
{
    NoEligibleDelivery,
    RelayAccepted,
    Deferred,
    TransportRetryScheduled,
    RejectedOrLeaseLost
}
