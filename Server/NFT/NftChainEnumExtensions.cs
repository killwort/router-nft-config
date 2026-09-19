namespace RouterNftConfig.Server.NFT;

internal static class NftChainEnumExtensions
{
    internal static string ToNftString(this NftChainType value) => value switch
    {
        NftChainType.Filter => "filter",
        NftChainType.Nat => "nat",
        NftChainType.Route => "route",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
    };

    internal static string ToNftString(this NftChainHook value) => value switch
    {
        NftChainHook.Prerouting => "prerouting",
        NftChainHook.Input => "input",
        NftChainHook.Forward => "forward",
        NftChainHook.Output => "output",
        NftChainHook.Postrouting => "postrouting",
        NftChainHook.Ingress => "ingress",
        NftChainHook.Egress => "egress",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
    };

    internal static string ToNftString(this NftChainPolicy value) => value switch
    {
        NftChainPolicy.Accept => "accept",
        NftChainPolicy.Drop => "drop",
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, null)
    };
}