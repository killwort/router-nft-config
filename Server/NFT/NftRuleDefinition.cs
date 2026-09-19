namespace RouterNftConfig.Server.NFT;

public sealed record NftRuleDefinition
{
    public NftRuleDefinition(string expression)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expression);
        if (expression.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("A rule expression must fit on one line.", nameof(expression));
        Expression = expression.Trim();
    }

    public string Expression { get; }
}