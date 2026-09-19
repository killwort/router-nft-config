using System.Text;

namespace RouterNftConfig.Server.NFT;

internal sealed record ReplaceChainTextMutation(
    NftChainRef Chain,
    IReadOnlyList<NftRuleDefinition> Rules) : NftMutation
{
    internal override void AppendCommand(StringBuilder output)
    {
        output.Append("flush chain ").AppendLine(Chain.ToNftPath());
        foreach (var rule in Rules)
            output.Append("add rule ").Append(Chain.ToNftPath()).Append(' ')
                .AppendLine(rule.Expression);
    }
}