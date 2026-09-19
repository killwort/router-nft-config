using System.Text;

namespace RouterNftConfig.Server.NFT;

internal sealed record ReplaceSetMutation(
    NftSetRef Set,
    IReadOnlyList<NftSetElement> Elements) : NftMutation
{
    internal override void AppendCommand(StringBuilder output)
    {
        output.Append("flush set ").AppendLine(Set.ToNftPath());
        if (Elements.Count > 0)
            output.Append("add element ").Append(Set.ToNftPath()).Append(" { ")
                .Append(string.Join(", ", Elements.Select(x => x.ToNftLiteral())))
                .AppendLine(" }");
    }
}