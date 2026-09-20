using System.Text;

namespace RouterNftConfig.Server.NFT;

internal sealed record AddSetElementMutation(NftSetRef Set, NftSetElement Element) : NftMutation
{
    internal override void AppendCommand(StringBuilder output) => output
        .Append("add element ").Append(Set.ToNftPath()).Append(" { ")
        .Append(Element.ToNftLiteral()).AppendLine(" }");
}