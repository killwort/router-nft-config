using System;
using System.Net;
using System.Net.NetworkInformation;

namespace RouterNftConfig.Server.DHCP;

public sealed record DhcpLease(
    IPAddress InetAddress,
    PhysicalAddress? EtherAddress,
    string? ClientHostname,
    DateTimeOffset? StartsAtUtc,
    DateTimeOffset? EndsAtUtc,
    bool NeverExpires,
    string BindingState)
{
    public bool IsActiveAt(DateTimeOffset instant) =>
        //string.Equals(BindingState, "active", StringComparison.OrdinalIgnoreCase) &&
        (StartsAtUtc is null || StartsAtUtc <= instant) &&
        (NeverExpires || EndsAtUtc is not null && EndsAtUtc > instant);
}