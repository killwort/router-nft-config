using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace RouterNftConfig.Server.ARP;

/// <summary>Reads a deterministic ARP snapshot from a JSON file for development and tests.</summary>
public sealed class ArpFileMockClient : IArpClient
{
    private readonly string _path;

    public ArpFileMockClient(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async Task<IReadOnlyList<ArpMapping>> GetMappingsAsync(
        CancellationToken cancellationToken = default)
    {
        var json = await File.ReadAllTextAsync(_path, cancellationToken).ConfigureAwait(false);
        return ArpJson.ParseMock(json);
    }
}
