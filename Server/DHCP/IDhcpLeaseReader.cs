using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace RouterNftConfig.Server.DHCP;

/// <summary>Reads the current assignments from a DHCP lease database.</summary>
public interface IDhcpLeaseReader
{
    /// <summary>Returns leases which are active at the time of the call.</summary>
    Task<IReadOnlyList<DhcpLease>> GetActiveLeasesAsync(
        CancellationToken cancellationToken = default);
}