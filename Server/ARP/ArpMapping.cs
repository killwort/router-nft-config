using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;

namespace RouterNftConfig.Server.ARP;

public sealed record ArpMapping(
    PhysicalAddress EtherAddress,
    IPAddress InetAddress,
    string Interface,
    IReadOnlyList<string> States);