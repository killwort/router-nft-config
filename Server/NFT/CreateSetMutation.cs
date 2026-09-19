using System.Text;

namespace RouterNftConfig.Server.NFT;

internal sealed record CreateSetMutation(NftSetRef Set, NftSetDefinition Definition) : NftMutation
{
    internal override void AppendCommand(StringBuilder output) => output
        .Append("create set ").Append(Set.ToNftPath()).Append(' ')
        .AppendLine(Definition.ToNftBody());
}