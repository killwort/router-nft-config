using System.Collections.Generic;

namespace RouterNftConfig.Server.Models;

public class Configuration
{
    public List<KnownHost> KnownHosts { get; set; } = [];
    public List<string> HiddenHosts { get; set; } = [];
    public List<FirewallAction> Actions { get; set; } = [];
}