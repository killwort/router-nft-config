using System.Text;

namespace RouterNftConfig.Server.NFT;

internal sealed record DeleteSetMutation(NftSetRef Set) : NftMutation
{
    internal override void AppendCommand(StringBuilder output) => output
        .Append("delete set ").AppendLine(Set.ToNftPath());
}