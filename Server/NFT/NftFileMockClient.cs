using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace RouterNftConfig.Server.NFT;

/// <summary>
/// A deterministic development double backed by a JSON file. High-level operations mutate the
/// simulated ruleset. Arbitrary batches are recorded under _mock.executedBatches but not parsed.
/// </summary>
public sealed class NftFileMockClient : INftablesClient, IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public NftFileMockClient(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async Task<NftExecutionResult> ExecuteBatchAsync(
        string batch,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(batch);
        await MutateAsync(root =>
        {
            var mock = root["_mock"] as JsonObject ?? new JsonObject();
            root["_mock"] = mock;
            var history = mock["executedBatches"] as JsonArray ?? new JsonArray();
            mock["executedBatches"] = history;
            history.Add(new JsonObject
            {
                ["timestampUtc"] = DateTimeOffset.UtcNow.ToString("O"),
                ["batch"] = batch
            });
        }, cancellationToken).ConfigureAwait(false);

        return new NftExecutionResult(0, string.Empty, string.Empty, IsSimulated: true, StateChanged: false);
    }

    public async Task<NftRuleset> ListRulesetAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var root = await LoadAsync(cancellationToken).ConfigureAwait(false);
            return NftRulesetJson.Parse(root.ToJsonString());
        }
        finally { _gate.Release(); }
    }

    public Task ReplaceSetAsync(
        NftSetRef set,
        IEnumerable<NftSetElement> elements,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(elements);
        var values = elements.Select(x => x.Value).ToArray();
        return MutateAsync(root =>
        {
            var setObject = FindDefinition(root, "set", set.Family, set.Table, set.Name)
                ?? throw new NftablesException($"Mock set '{set.ToNftPath()}' does not exist.");
            setObject["elem"] = new JsonArray(
                values.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        }, cancellationToken);
    }

    public Task ReplaceChainAsync(
        NftChainRef chain,
        IEnumerable<NftRuleDefinition> rules,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(rules);
        var materialized = rules.ToArray();
        return MutateAsync(root =>
        {
            var nftables = RequireNftables(root);
            var chainIndex = FindDefinitionIndex(nftables, "chain", chain.Family, chain.Table, chain.Name);
            if (chainIndex < 0)
                throw new NftablesException($"Mock chain '{chain.ToNftPath()}' does not exist.");

            for (var i = nftables.Count - 1; i >= 0; i--)
            {
                if (IsRuleFor(nftables[i], chain)) nftables.RemoveAt(i);
            }

            chainIndex = FindDefinitionIndex(nftables, "chain", chain.Family, chain.Table, chain.Name);
            var insertionIndex = chainIndex + 1;
            foreach (var rule in materialized)
            {
                nftables.Insert(insertionIndex++, new JsonObject
                {
                    ["rule"] = new JsonObject
                    {
                        ["family"] = chain.Family.ToNftString(),
                        ["table"] = chain.Table,
                        ["chain"] = chain.Name,
                        ["expr"] = new JsonArray(),
                        ["mock_expression"] = rule.Expression
                    }
                });
            }
        }, cancellationToken);
    }

    private async Task MutateAsync(Action<JsonObject> mutation, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var root = await LoadAsync(cancellationToken).ConfigureAwait(false);
            mutation(root);
            await SaveAtomicallyAsync(root, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private async Task<JsonObject> LoadAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path)) return CreateEmptyState();
        await using var stream = new FileStream(
            _path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var node = await JsonNode.ParseAsync(stream, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return node as JsonObject ?? throw new JsonException("Mock state root must be a JSON object.");
    }

    private async Task SaveAtomicallyAsync(JsonObject root, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(_path)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (var stream = new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, root, JsonOptions, cancellationToken)
                    .ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            File.Move(temporary, _path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static JsonObject CreateEmptyState() => new()
    {
        ["nftables"] = new JsonArray
        {
            new JsonObject
            {
                ["metainfo"] = new JsonObject
                {
                    ["version"] = "file-mock",
                    ["release_name"] = "development",
                    ["json_schema_version"] = 1
                }
            }
        },
        ["_mock"] = new JsonObject { ["executedBatches"] = new JsonArray() }
    };

    private static JsonArray RequireNftables(JsonObject root) =>
        root["nftables"] as JsonArray
        ?? throw new JsonException("Mock state must contain an 'nftables' array.");

    private static JsonObject? FindDefinition(
        JsonObject root, string kind, NftFamily family, string table, string name)
    {
        var nftables = RequireNftables(root);
        var index = FindDefinitionIndex(nftables, kind, family, table, name);
        return index < 0 ? null : nftables[index]?[kind] as JsonObject;
    }

    private static int FindDefinitionIndex(
        JsonArray nftables, string kind, NftFamily family, string table, string name)
    {
        for (var i = 0; i < nftables.Count; i++)
        {
            if (nftables[i]?[kind] is not JsonObject definition) continue;
            if (String(definition, "family") == family.ToNftString() &&
                String(definition, "table") == table && String(definition, "name") == name)
                return i;
        }
        return -1;
    }

    private static bool IsRuleFor(JsonNode? node, NftChainRef chain) =>
        node?["rule"] is JsonObject rule &&
        String(rule, "family") == chain.Family.ToNftString() &&
        String(rule, "table") == chain.Table && String(rule, "chain") == chain.Name;

    private static string? String(JsonObject obj, string property) =>
        obj[property]?.GetValue<string>();

    public ValueTask DisposeAsync()
    {
        _gate.Dispose();
        return ValueTask.CompletedTask;
    }
}
