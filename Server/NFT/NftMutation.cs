using System.Text;

namespace RouterNftConfig.Server.NFT;

internal abstract record NftMutation
{
    internal abstract void AppendCommand(StringBuilder output);
}