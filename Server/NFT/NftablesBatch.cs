namespace RouterNftConfig.Server.NFT;

public sealed class NftablesBatch : INftablesBatch
{
    private readonly Func<IReadOnlyList<NftMutation>, CancellationToken, Task<NftExecutionResult>>
        _executor;
    private readonly List<NftMutation> _mutations = [];
    private int _executed;

    internal NftablesBatch(
        Func<IReadOnlyList<NftMutation>, CancellationToken, Task<NftExecutionResult>> executor) =>
        _executor = executor;

    public int Count => _mutations.Count;

    public INftablesBatch CreateSet(NftSetRef set, NftSetDefinition definition)
    {
        EnsureMutable();
        ArgumentNullException.ThrowIfNull(definition);
        _ = set.ToNftPath();
        definition.Validate();
        var snapshot = definition with
        {
            Flags = definition.Flags.ToArray(),
            InitialElements = definition.InitialElements.ToArray()
        };
        _mutations.Add(new CreateSetMutation(set, snapshot));
        return this;
    }

    public INftablesBatch DeleteSet(NftSetRef set)
    {
        EnsureMutable();
        _ = set.ToNftPath();
        _mutations.Add(new DeleteSetMutation(set));
        return this;
    }

    public INftablesBatch CreateChain(NftChainRef chain, NftChainDefinition definition)
    {
        EnsureMutable();
        ArgumentNullException.ThrowIfNull(definition);
        _ = chain.ToNftPath();
        definition.Validate();
        _mutations.Add(new CreateChainMutation(chain, definition with { }));
        return this;
    }

    public INftablesBatch CreateChain(NftChainRef chain) =>
        CreateChain(chain, new NftChainDefinition());

    public INftablesBatch ReplaceSet(NftSetRef set, IEnumerable<NftSetElement> elements)
    {
        EnsureMutable();
        ArgumentNullException.ThrowIfNull(elements);
        _ = set.ToNftPath();
        var snapshot = elements.ToArray();
        if (snapshot.Any(x => x is null))
            throw new ArgumentException("Set elements cannot contain null.", nameof(elements));
        _mutations.Add(new ReplaceSetMutation(set, snapshot));
        return this;
    }

    public INftablesBatch ReplaceChain(NftChainRef chain, IEnumerable<NftRuleDefinition> rules)
    {
        EnsureMutable();
        ArgumentNullException.ThrowIfNull(rules);
        _ = chain.ToNftPath();
        var snapshot = rules.ToArray();
        if (snapshot.Any(x => x is null))
            throw new ArgumentException("Chain rules cannot contain null.", nameof(rules));
        _mutations.Add(new ReplaceChainTextMutation(chain, snapshot));
        return this;
    }

    public INftablesBatch ReplaceChain(NftChainRef chain, IEnumerable<NftRule> rules)
    {
        EnsureMutable();
        ArgumentNullException.ThrowIfNull(rules);
        _ = chain.ToNftPath();
        var snapshot = rules.Select(rule =>
        {
            ArgumentNullException.ThrowIfNull(rule);
            return new NftRuleSnapshot(
                rule.Expressions.Select(expression => expression.Clone()).ToArray(),
                rule.Comment,
                rule.MockExpression);
        }).ToArray();
        _mutations.Add(new ReplaceChainParsedMutation(chain, snapshot));
        return this;
    }

    public Task<NftExecutionResult> ExecuteAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _executed, 1) != 0)
            throw new InvalidOperationException("An nftables batch can only be executed once.");
        return _executor(_mutations.ToArray(), cancellationToken);
    }

    private void EnsureMutable()
    {
        if (Volatile.Read(ref _executed) != 0)
            throw new InvalidOperationException("The nftables batch has already been executed.");
    }
}