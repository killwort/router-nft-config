namespace RouterNftConfig.Server.NFT;

internal static class NftSetEnumExtensions
{
    public static string ToNftString(this NftSetDataType type) => type switch
    {
        NftSetDataType.EtherAddress => "ether_addr",
        NftSetDataType.IPv4Address => "ipv4_addr",
        NftSetDataType.IPv6Address => "ipv6_addr",
        NftSetDataType.InetProtocol => "inet_proto",
        NftSetDataType.InetService => "inet_service",
        NftSetDataType.Mark => "mark",
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
    };

    public static string ToNftString(this NftSetFlag flag) => flag switch
    {
        NftSetFlag.Constant => "constant",
        NftSetFlag.Dynamic => "dynamic",
        NftSetFlag.Interval => "interval",
        NftSetFlag.Timeout => "timeout",
        _ => throw new ArgumentOutOfRangeException(nameof(flag), flag, null)
    };

    public static string ToNftString(this NftSetPolicy policy) => policy switch
    {
        NftSetPolicy.Performance => "performance",
        NftSetPolicy.Memory => "memory",
        _ => throw new ArgumentOutOfRangeException(nameof(policy), policy, null)
    };
}