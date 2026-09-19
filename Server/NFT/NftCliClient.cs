using System.Diagnostics;

namespace RouterNftConfig.Server.NFT;

public sealed class NftCliClient : INftablesClient
{
    private readonly string _executable;

    public NftCliClient(string executable = "nft")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executable);
        _executable = executable;
    }

    public Task<NftExecutionResult> ExecuteBatchAsync(
        string batch,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(batch);
        return RunAsync(["-f", "-"], batch, cancellationToken);
    }

    public async Task<NftRuleset> ListRulesetAsync(CancellationToken cancellationToken = default)
    {
        var result = await RunAsync(["-j", "list", "ruleset"], null, cancellationToken)
            .ConfigureAwait(false);
        EnsureSuccess(result, "nft -j list ruleset");
        return NftRulesetJson.Parse(result.StandardOutput);
    }

    public INftablesBatch CreateBatch() => new NftablesBatch(ExecuteMutationsAsync);

    private async Task<NftExecutionResult> ExecuteMutationsAsync(
        IReadOnlyList<NftMutation> mutations,
        CancellationToken cancellationToken)
    {
        if (mutations.Count == 0)
            return new NftExecutionResult(0, string.Empty, string.Empty, StateChanged: false);

        var script = NftMutationBatchRenderer.RenderText(mutations);
        //Console.WriteLine($"nft -f {script}");
        var result = await ExecuteBatchAsync(script, cancellationToken).ConfigureAwait(false);
        EnsureSuccess(result, "execute mutation batch");
        return result;
    }

    private async Task<NftExecutionResult> RunAsync(
        IEnumerable<string> arguments,
        string? standardInput,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _executable,
            UseShellExecute = false,
            RedirectStandardInput = standardInput is not null,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start()) throw new InvalidOperationException($"Could not start '{_executable}'.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new NftablesException($"Could not start '{_executable}'.", null, null, ex);
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        if (standardInput is not null)
        {
            await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken)
                .ConfigureAwait(false);
            await process.StandardInput.DisposeAsync().ConfigureAwait(false);
        }

        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already exited */ }
            throw;
        }

        return new NftExecutionResult(
            process.ExitCode,
            await stdoutTask.ConfigureAwait(false),
            await stderrTask.ConfigureAwait(false));
    }

    private static void EnsureSuccess(NftExecutionResult result, string operation)
    {
        if (result.ExitCode != 0)
            throw new NftablesException(
                $"nftables operation '{operation}' failed with exit code {result.ExitCode}: " +
                result.StandardError.Trim(), result.ExitCode, result.StandardError);
    }
}