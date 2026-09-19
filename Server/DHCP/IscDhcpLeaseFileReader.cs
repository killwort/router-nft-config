using System.Text;

namespace RouterNftConfig.Server.DHCP;

/// <summary>Reads active DHCPv4 assignments from an ISC DHCP <c>dhcpd.leases</c> file.</summary>
public sealed class IscDhcpLeaseFileReader : IDhcpLeaseReader
{
    private readonly string _path;
    private readonly TimeProvider _timeProvider;

    public IscDhcpLeaseFileReader(
        string path = "/var/lib/dhcp/dhcpd.leases",
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<IReadOnlyList<DhcpLease>> GetActiveLeasesAsync(
        CancellationToken cancellationToken = default)
    {
        await using var stream = new FileStream(
            _path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 16 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var contents = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var now = _timeProvider.GetUtcNow();
        return IscDhcpLeaseParser.ParseLatest(contents)
            .Where(x => x.IsActiveAt(now))
            .ToArray();
    }
}