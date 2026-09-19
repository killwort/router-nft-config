using System.Text;

namespace RouterNftConfig.Server.NFT;

internal sealed record CreateChainMutation(
    NftChainRef Chain,
    NftChainDefinition Definition) : NftMutation
{
    internal override void AppendCommand(StringBuilder output)
    {
        output.Append("create chain ").Append(Chain.ToNftPath());
        if (Definition.ToNftBody() is { } body) output.Append(' ').Append(body);
        output.AppendLine();
    }
}