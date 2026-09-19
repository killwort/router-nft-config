using System.Text;

namespace RouterNftConfig.Server.NFT;

internal sealed record ReplaceChainParsedMutation(
    NftChainRef Chain,
    IReadOnlyList<NftRuleSnapshot> Rules) : NftMutation
{
    internal override void AppendCommand(StringBuilder output)
    {
        output.Append("flush chain ").AppendLine(Chain.ToNftPath());
        foreach (var rule in Rules)
            output.Append("add rule ").Append(Chain.ToNftPath()).Append(' ')
                .AppendLine(NftRuleTextRenderer.Render(
                    rule.Expressions, rule.Comment, rule.MockExpression));
    }
}