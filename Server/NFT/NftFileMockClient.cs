using System.Text.Json;
using System.Text.Json.Nodes;

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

    public INftablesBatch CreateBatch() => new NftablesBatch(ExecuteMutationsAsync);

    private async Task<NftExecutionResult> ExecuteMutationsAsync(
        IReadOnlyList<NftMutation> mutations,
        CancellationToken cancellationToken)
    {
        if (mutations.Count == 0)
            return new NftExecutionResult(
                0, string.Empty, string.Empty, IsSimulated: true, StateChanged: false);

        await MutateAsync(root =>
        {
            foreach (var mutation in mutations)
            {
                switch (mutation)
                {
                    case CreateSetMutation createSet:
                        ApplyCreateSet(root, createSet);
                        break;
                    case DeleteSetMutation deleteSet:
                        ApplyDeleteSet(root, deleteSet);
                        break;
                    case CreateChainMutation createChain:
                        ApplyCreateChain(root, createChain);
                        break;
                    case ReplaceSetMutation replaceSet:
                        ApplyReplaceSet(root, replaceSet);
                        break;
                    case ReplaceChainTextMutation replaceChainText:
                        ApplyReplaceChain(root, replaceChainText);
                        break;
                    case ReplaceChainParsedMutation replaceChainParsed:
                        ApplyReplaceChain(root, replaceChainParsed);
                        break;
                    default:
                        throw new NotSupportedException(
                            $"Unsupported mock mutation '{mutation.GetType().Name}'.");
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        return new NftExecutionResult(
            0, string.Empty, string.Empty, IsSimulated: true, StateChanged: true);
    }

    private static void ApplyCreateSet(JsonObject root, CreateSetMutation operation)
    {
        var set = operation.Set;
        var definition = operation.Definition;
        var nftables = RequireNftables(root);
        if (FindTableIndex(nftables, set.Family, set.Table) < 0)
            throw new NftablesException(
                $"Mock table '{set.Family.ToNftString()} {set.Table}' does not exist.");
        if (FindDefinition(root, "set", set.Family, set.Table, set.Name) is not null)
            throw new NftablesException($"Mock set '{set.ToNftPath()}' already exists.");

        var flags = definition.EffectiveFlags().Select(x => x.ToNftString()).ToArray();
        var elements = definition.InitialElements.Select(x => x.Value).ToArray();
        var body = new JsonObject
        {
            ["family"] = set.Family.ToNftString(),
            ["table"] = set.Table,
            ["name"] = set.Name,
            ["type"] = definition.Type.ToNftString(),
            ["elem"] = new JsonArray(
                elements.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray())
        };
        if (flags.Length > 0)
            body["flags"] = new JsonArray(
                flags.Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        if (definition.Timeout is { } timeout)
            body["timeout"] = NftSetDefinition.ToWholeSeconds(timeout, nameof(definition.Timeout));
        if (definition.GarbageCollectionInterval is { } gcInterval)
            body["gc-interval"] = NftSetDefinition.ToWholeSeconds(
                gcInterval, nameof(definition.GarbageCollectionInterval));
        if (definition.Size is { } size) body["size"] = size;
        if (definition.Policy is { } policy) body["policy"] = policy.ToNftString();
        if (definition.AutoMerge) body["auto-merge"] = true;
        if (!string.IsNullOrWhiteSpace(definition.Comment)) body["comment"] = definition.Comment;

        var tableIndex = FindTableIndex(nftables, set.Family, set.Table);
        nftables.Insert(tableIndex + 1, new JsonObject { ["set"] = body });
    }

    private static void ApplyDeleteSet(JsonObject root, DeleteSetMutation operation)
    {
        var set = operation.Set;
        var nftables = RequireNftables(root);
        var index = FindDefinitionIndex(nftables, "set", set.Family, set.Table, set.Name);
        if (index < 0) throw new NftablesException($"Mock set '{set.ToNftPath()}' does not exist.");
        nftables.RemoveAt(index);
    }

    private static void ApplyCreateChain(JsonObject root, CreateChainMutation operation)
    {
        var chain = operation.Chain;
        var definition = operation.Definition;
        var nftables = RequireNftables(root);
        var tableIndex = FindTableIndex(nftables, chain.Family, chain.Table);
        if (tableIndex < 0)
            throw new NftablesException(
                $"Mock table '{chain.Family.ToNftString()} {chain.Table}' does not exist.");
        if (FindDefinition(root, "chain", chain.Family, chain.Table, chain.Name) is not null)
            throw new NftablesException($"Mock chain '{chain.ToNftPath()}' already exists.");

        var body = new JsonObject
        {
            ["family"] = chain.Family.ToNftString(),
            ["table"] = chain.Table,
            ["name"] = chain.Name
        };
        if (definition.Type is { } type)
        {
            body["type"] = type.ToNftString();
            body["hook"] = definition.Hook!.Value.ToNftString();
            body["prio"] = definition.Priority!.Value;
            if (!string.IsNullOrWhiteSpace(definition.Device)) body["dev"] = definition.Device;
            if (definition.Policy is { } policy) body["policy"] = policy.ToNftString();
        }
        if (!string.IsNullOrWhiteSpace(definition.Comment)) body["comment"] = definition.Comment;
        nftables.Insert(tableIndex + 1, new JsonObject { ["chain"] = body });
    }

    private static void ApplyReplaceSet(JsonObject root, ReplaceSetMutation operation)
    {
        var set = operation.Set;
        var setObject = FindDefinition(root, "set", set.Family, set.Table, set.Name)
            ?? throw new NftablesException($"Mock set '{set.ToNftPath()}' does not exist.");
        setObject["elem"] = new JsonArray(
            operation.Elements.Select(x => (JsonNode?)JsonValue.Create(x.Value)).ToArray());
    }

    private static void ApplyReplaceChain(JsonObject root, ReplaceChainTextMutation operation)
    {
        var chain = operation.Chain;
        var (nftables, insertionIndex) = FlushChainRules(root, chain);
        foreach (var rule in operation.Rules)
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
    }

    private static void ApplyReplaceChain(JsonObject root, ReplaceChainParsedMutation operation)
    {
        var chain = operation.Chain;
        var (nftables, insertionIndex) = FlushChainRules(root, chain);
        foreach (var rule in operation.Rules)
        {
            _ = NftRuleTextRenderer.Render(
                rule.Expressions, rule.Comment, rule.MockExpression);
            var expressions = new JsonArray(rule.Expressions
                .Select(expression => JsonNode.Parse(expression.GetRawText()))
                .ToArray());
            var body = new JsonObject
            {
                ["family"] = chain.Family.ToNftString(),
                ["table"] = chain.Table,
                ["chain"] = chain.Name,
                ["expr"] = expressions
            };
            if (!string.IsNullOrWhiteSpace(rule.Comment)) body["comment"] = rule.Comment;
            if (!string.IsNullOrWhiteSpace(rule.MockExpression))
                body["mock_expression"] = rule.MockExpression;
            nftables.Insert(insertionIndex++, new JsonObject { ["rule"] = body });
        }
    }

    private static (JsonArray Nftables, int InsertionIndex) FlushChainRules(
        JsonObject root,
        NftChainRef chain)
    {
        var nftables = RequireNftables(root);
        var chainIndex = FindDefinitionIndex(nftables, "chain", chain.Family, chain.Table, chain.Name);
        if (chainIndex < 0)
            throw new NftablesException($"Mock chain '{chain.ToNftPath()}' does not exist.");

        for (var i = nftables.Count - 1; i >= 0; i--)
            if (IsRuleFor(nftables[i], chain)) nftables.RemoveAt(i);

        chainIndex = FindDefinitionIndex(nftables, "chain", chain.Family, chain.Table, chain.Name);
        return (nftables, chainIndex + 1);
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

    private static int FindTableIndex(JsonArray nftables, NftFamily family, string name)
    {
        for (var i = 0; i < nftables.Count; i++)
        {
            if (nftables[i]?["table"] is not JsonObject table) continue;
            if (String(table, "family") == family.ToNftString() && String(table, "name") == name)
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
