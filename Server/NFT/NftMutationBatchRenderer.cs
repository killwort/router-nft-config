using System.Text;

namespace RouterNftConfig.Server.NFT;

internal static class NftMutationBatchRenderer
{
    internal static string RenderText(IReadOnlyList<NftMutation> mutations)
    {
        var script = new StringBuilder();
        foreach (var mutation in mutations) mutation.AppendCommand(script);
        return script.ToString();
    }
}