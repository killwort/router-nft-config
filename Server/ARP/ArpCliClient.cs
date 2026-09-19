using System.Diagnostics;

namespace RouterNftConfig.Server.ARP;

/// <summary>Reads the kernel ARP table through <c>ip -4 -j neighbour show</c>.</summary>
public sealed class ArpCliClient : IArpClient
{
    private readonly string _executable;

    public ArpCliClient(string executable = "ip")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        _executable = executable;
    }

    public async Task<IReadOnlyList<ArpMapping>> GetMappingsAsync(
        CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "-4", "-j", "neighbour", "show" })
            startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start()) throw new InvalidOperationException($"Could not start '{_executable}'.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new ArpException($"Could not start '{_executable}'.", null, null, ex);
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already exited */ }
            throw;
        }

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);
        if (process.ExitCode != 0)
            throw new ArpException(
                $"Reading the ARP table failed with exit code {process.ExitCode}: {stderr.Trim()}",
                process.ExitCode,
                stderr);

        return ArpJson.ParseIpNeighbour(stdout);
    }
}