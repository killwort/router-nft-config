namespace RouterNftConfig.Server.ARP;

/// <summary>Reads the current IPv4 neighbour (ARP) table.</summary>
public interface IArpClient
{
    /// <summary>
    /// Returns a point-in-time snapshot of resolved IPv4-to-Ethernet neighbour mappings.
    /// One Ethernet address may occur in several records.
    /// </summary>
    Task<IReadOnlyList<ArpMapping>> GetMappingsAsync(
        CancellationToken cancellationToken = default);
}