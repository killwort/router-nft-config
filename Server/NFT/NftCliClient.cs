using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

    public async Task ReplaceSetAsync(
        NftSetRef set,
        IEnumerable<NftSetElement> elements,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(elements);
        var materialized = elements.ToArray();
        var batch = new StringBuilder()
            .Append("flush set ").AppendLine(set.ToNftPath());
        if (materialized.Length > 0)
        {
            batch.Append("add element ").Append(set.ToNftPath()).Append(" { ")
                .Append(string.Join(", ", materialized.Select(x => x.ToNftLiteral())))
                .AppendLine(" }");
        }

        var result = await ExecuteBatchAsync(batch.ToString(), cancellationToken).ConfigureAwait(false);
        EnsureSuccess(result, $"replace set {set.ToNftPath()}");
    }

    public async Task ReplaceChainAsync(
        NftChainRef chain,
        IEnumerable<NftRuleDefinition> rules,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var batch = new StringBuilder()
            .Append("flush chain ").AppendLine(chain.ToNftPath());
        foreach (var rule in rules)
            batch.Append("add rule ").Append(chain.ToNftPath()).Append(' ')
                .AppendLine(rule.Expression);

        var result = await ExecuteBatchAsync(batch.ToString(), cancellationToken).ConfigureAwait(false);
        EnsureSuccess(result, $"replace chain {chain.ToNftPath()}");
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