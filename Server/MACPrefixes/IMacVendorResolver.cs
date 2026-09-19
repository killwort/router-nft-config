using System.Net.NetworkInformation;

namespace RouterNftConfig.Server.MACPrefixes;

/// <summary>Resolves globally administered Ethernet addresses to IEEE assignees.</summary>
public interface IMacVendorResolver
{
    /// <summary>Returns the IEEE organization name, or <see langword="null"/> when unknown.</summary>
    Task<string?> ResolveAsync(
        PhysicalAddress macAddress,
        CancellationToken cancellationToken = default);
}
