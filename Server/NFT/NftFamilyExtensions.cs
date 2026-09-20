using System.Linq;

namespace RouterNftConfig.Server.NFT;

public static class NftFamilyExtensions
{
    public static string ToNftString(this NftFamily family) => family switch
    {
        NftFamily.Ip => "ip",
        NftFamily.Ip6 => "ip6",
        NftFamily.Inet => "inet",
        NftFamily.Arp => "arp",
        NftFamily.Bridge => "bridge",
        NftFamily.Netdev => "netdev",
        _ => throw new ArgumentOutOfRangeException(nameof(family), family, null)
    };

    public static NftFamily ParseNftFamily(string value) => value switch
    {
        "ip" => NftFamily.Ip,
        "ip6" => NftFamily.Ip6,
        "inet" => NftFamily.Inet,
        "arp" => NftFamily.Arp,
        "bridge" => NftFamily.Bridge,
        "netdev" => NftFamily.Netdev,
        _ => throw new FormatException($"Unknown nftables family '{value}'.")
    };
}