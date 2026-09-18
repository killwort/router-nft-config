using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace RouterNftConfig.Server.MACPrefixes;

/// <summary>
/// Downloads and caches the IEEE MA-L, MA-M, MA-S and legacy IAB registries, then resolves
/// EUI-48 addresses using longest-prefix matching.
/// </summary>
public sealed class IeeeMacVendorResolver : IMacVendorResolver, IDisposable
{
    private static readonly Source[] Sources =
    [
        new("ma-l.csv", new("https://standards-oui.ieee.org/oui/oui.csv"), 24),
        new("ma-m.csv", new("https://standards-oui.ieee.org/oui28/mam.csv"), 28),
        new("iab.csv", new("https://standards-oui.ieee.org/iab/iab.csv"), 36),
        // Load MA-S after legacy IAB so a current assignment wins an unlikely exact collision.
        new("ma-s.csv", new("https://standards-oui.ieee.org/oui36/oui36.csv"), 36)
    ];

    private readonly string _cacheDirectory;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly TimeSpan _cacheLifetime;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile PrefixIndex? _index;
    private long _nextRefreshCheckUtcTicks;
    private bool _disposed;

    public IeeeMacVendorResolver(
        string cacheDirectory=null,
        HttpClient? httpClient = null,
        TimeSpan? cacheLifetime = null)
    {
        if (cacheDirectory == null) cacheDirectory = Environment.CurrentDirectory;
        //ArgumentException.ThrowIfNullOrWhiteSpace(cacheDirectory);
        _cacheDirectory = Path.GetFullPath(cacheDirectory);
        _cacheLifetime = cacheLifetime ?? TimeSpan.FromDays(7);
        if (_cacheLifetime < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(
                nameof(cacheLifetime), "Cache lifetime cannot be negative.");

        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public async Task<string?> ResolveAsync(
        PhysicalAddress macAddress,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(macAddress);
        var bytes = macAddress.GetAddressBytes();
        if (bytes.Length != 6)
            throw new ArgumentException("An EUI-48 address must contain exactly 6 bytes.", nameof(macAddress));

        // The IEEE registries do not identify locally administered/randomized or group addresses.
        if ((bytes[0] & 0x02) != 0 || (bytes[0] & 0x01) != 0) return null;

        var index = await EnsureIndexAsync(cancellationToken).ConfigureAwait(false);
        return index.Resolve(ToUInt48(bytes));
    }

    private async Task<PrefixIndex> EnsureIndexAsync(CancellationToken cancellationToken)
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var current = _index;
        if (current is not null && nowTicks < Interlocked.Read(ref _nextRefreshCheckUtcTicks))
            return current;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            nowTicks = DateTime.UtcNow.Ticks;
            current = _index;
            if (current is not null && nowTicks < Interlocked.Read(ref _nextRefreshCheckUtcTicks))
                return current;

            Directory.CreateDirectory(_cacheDirectory);
            foreach (var source in Sources)
            {
                var path = Path.Combine(_cacheDirectory, source.FileName);
                if (!IsFresh(path)) await RefreshWithFallbackAsync(source, path, cancellationToken)
                    .ConfigureAwait(false);
            }

            current = await LoadIndexAsync(cancellationToken).ConfigureAwait(false);
            _index = current;
            var next = DateTime.UtcNow + _cacheLifetime;
            Interlocked.Exchange(ref _nextRefreshCheckUtcTicks, next.Ticks);
            return current;
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool IsFresh(string path) =>
        File.Exists(path) && DateTime.UtcNow - File.GetLastWriteTimeUtc(path) < _cacheLifetime;

    private async Task RefreshWithFallbackAsync(
        Source source,
        string destination,
        CancellationToken cancellationToken)
    {
        try
        {
            await DownloadAtomicallyAsync(source.Uri, destination, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (
            !cancellationToken.IsCancellationRequested && File.Exists(destination))
        {
            // HttpClient timeout: a stale but valid cache is preferable to losing resolution.
        }
        catch (HttpRequestException) when (File.Exists(destination))
        {
            // Offline: use stale cache. With no cache, let the exception reach the caller.
        }
        catch (InvalidDataException) when (File.Exists(destination))
        {
            // Do not replace a usable stale cache with an unexpected HTTP response body.
        }
        catch (IOException) when (File.Exists(destination))
        {
            // A concurrent process may have refreshed the same cache file.
        }
    }

    private async Task DownloadAtomicallyAsync(
        Uri uri,
        string destination,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Nftables.Net", "1.0"));
        using var response = await _httpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var temporary = Path.Combine(
            _cacheDirectory, $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var output = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await response.Content.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            await ValidateDownloadedCsvAsync(temporary, cancellationToken).ConfigureAwait(false);
            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static async Task ValidateDownloadedCsvAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = OpenCacheFile(path);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        var firstLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (firstLine is null ||
            !firstLine.Contains("Assignment", StringComparison.Ordinal) ||
            !firstLine.Contains("Organization Name", StringComparison.Ordinal))
            throw new InvalidDataException("The downloaded IEEE file does not have the expected CSV header.");
    }

    private async Task<PrefixIndex> LoadIndexAsync(CancellationToken cancellationToken)
    {
        var index = new PrefixIndex();
        foreach (var source in Sources)
        {
            var path = Path.Combine(_cacheDirectory, source.FileName);
            var contents = await ReadCacheFileAsync(path, cancellationToken).ConfigureAwait(false);
            foreach (var row in Csv.Parse(contents))
            {
                if (row.Count < 3 || row[1] == "Assignment") continue;
                var assignment = row[1].Trim();
                var organization = row[2].Trim();
                var requiredDigits = (source.PrefixLength + 3) / 4;
                if (organization.Length == 0 || assignment.Length != requiredDigits ||
                    !ulong.TryParse(
                        assignment,
                        NumberStyles.AllowHexSpecifier,
                        CultureInfo.InvariantCulture,
                        out var prefix))
                    continue;
                index.Add(source.PrefixLength, prefix, organization);
            }
        }
        return index;
    }

    private static async Task<string> ReadCacheFileAsync(
        string path,
        CancellationToken cancellationToken)
    {
        await using var stream = OpenCacheFile(path);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    private static FileStream OpenCacheFile(string path) => new(
        path,
        FileMode.Open,
        FileAccess.Read,
        FileShare.ReadWrite | FileShare.Delete,
        bufferSize: 64 * 1024,
        FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static ulong ToUInt48(IReadOnlyList<byte> bytes)
    {
        ulong result = 0;
        for (var i = 0; i < 6; i++) result = (result << 8) | bytes[i];
        return result;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _gate.Dispose();
        if (_ownsHttpClient) _httpClient.Dispose();
    }

    private sealed record Source(string FileName, Uri Uri, int PrefixLength);

    private sealed class PrefixIndex
    {
        private readonly Dictionary<ulong, string> _prefix24 = new();
        private readonly Dictionary<ulong, string> _prefix28 = new();
        private readonly Dictionary<ulong, string> _prefix36 = new();

        public void Add(int length, ulong prefix, string organization)
        {
            var target = length switch
            {
                24 => _prefix24,
                28 => _prefix28,
                36 => _prefix36,
                _ => throw new ArgumentOutOfRangeException(nameof(length))
            };
            target[prefix] = organization;
        }

        public string? Resolve(ulong macAddress)
        {
            if (_prefix36.TryGetValue(macAddress >> 12, out var result)) return result;
            if (_prefix28.TryGetValue(macAddress >> 20, out result)) return result;
            return _prefix24.TryGetValue(macAddress >> 24, out result) ? result : null;
        }
    }

    private static class Csv
    {
        public static IEnumerable<IReadOnlyList<string>> Parse(string value)
        {
            var row = new List<string>();
            var field = new StringBuilder();
            var quoted = false;

            for (var i = 0; i < value.Length; i++)
            {
                var ch = value[i];
                if (quoted)
                {
                    if (ch == '"')
                    {
                        if (i + 1 < value.Length && value[i + 1] == '"')
                        {
                            field.Append('"');
                            i++;
                        }
                        else quoted = false;
                    }
                    else field.Append(ch);
                    continue;
                }

                switch (ch)
                {
                    case '"':
                        quoted = true;
                        break;
                    case ',':
                        row.Add(field.ToString());
                        field.Clear();
                        break;
                    case '\r':
                        if (i + 1 < value.Length && value[i + 1] == '\n') i++;
                        row.Add(field.ToString());
                        field.Clear();
                        yield return row;
                        row = [];
                        break;
                    case '\n':
                        row.Add(field.ToString());
                        field.Clear();
                        yield return row;
                        row = [];
                        break;
                    default:
                        field.Append(ch);
                        break;
                }
            }

            if (field.Length > 0 || row.Count > 0)
            {
                row.Add(field.ToString());
                yield return row;
            }
        }
    }
}
