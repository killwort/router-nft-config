using System.Diagnostics;
using System.Net.NetworkInformation;
using Microsoft.AspNetCore.Mvc;
using RouterNftConfig.Server.ARP;
using RouterNftConfig.Server.DHCP;
using RouterNftConfig.Server.MACPrefixes;
using RouterNftConfig.Server.Models;
using RouterNftConfig.Server.NFT;
using Host = RouterNftConfig.Server.Models.Host;

namespace RouterNftConfig.Server
{
    [Route("api")]
    public class ApiController : Microsoft.AspNetCore.Mvc.Controller
    {
        private readonly NftManager _manager;
        private readonly INftablesClient _nftClient;
        private readonly IArpClient _arpClient;
        private readonly IDhcpLeaseReader _dhcpLeaseReader;
        private readonly IMacVendorResolver _macVendorResolver;

        public ApiController(NftManager manager, INftablesClient nftClient, IArpClient arpClient, IDhcpLeaseReader dhcpLeaseReader, IMacVendorResolver macVendorResolver)
        {
            _manager = manager;
            _nftClient = nftClient;
            _arpClient = arpClient;
            _dhcpLeaseReader = dhcpLeaseReader;
            _macVendorResolver = macVendorResolver;
        }

        [HttpGet("rules")]
        public async Task<NftRuleset> GetRuleset()
        {
            var ruleset = await _nftClient.ListRulesetAsync();
            return ruleset;
        }


        [HttpGet("hide/{mac}")]
        public async Task HideHost([FromRoute] string mac)
        {
            var config = await _manager.GetConfiguration();
            config.HiddenHosts.Add(PhysicalAddress.Parse(mac).ToString());
            await _manager.SaveConfiguration(config);
        }

        [HttpGet("unhide/{mac}")]
        public async Task UnhideHost([FromRoute] string mac)
        {
            var config = await _manager.GetConfiguration();
            config.HiddenHosts.Remove(PhysicalAddress.Parse(mac).ToString());
            await _manager.SaveConfiguration(config);
        }

        [HttpPost]
        public async Task UpdateHost([FromBody] UpdateHostRequest request)
        {
            var config = await _manager.GetConfiguration();
            var knownHost = config.KnownHosts.FirstOrDefault(z => PhysicalAddress.Parse(z.MacAddress).Equals(PhysicalAddress.Parse(request.MacAddress)));
            if (knownHost == null)
            {
                config.KnownHosts.Add(knownHost = new KnownHost
                {
                    MacAddress = PhysicalAddress.Parse(request.MacAddress).ToString()
                });
            }

            knownHost.Name = request.Name;
            knownHost.Groups = request.Groups ?? [];
            await _manager.SaveConfiguration(config);
            await _manager.UpdateSets();
        }

        [HttpPost("action")]
        public async Task UpdateAction([FromBody] UpdateActionRequest request)
        {
            var config = await _manager.GetConfiguration();
            FirewallAction action;
            if (string.IsNullOrEmpty(request.Id))
            {
                action = new FirewallAction(request);
                action.Id = Guid.NewGuid().ToString("N");
                config.Actions.Add(action);
            }
            else
            {
                action = config.Actions.First(x => string.Equals(x.Id, request.Id, StringComparison.OrdinalIgnoreCase));
            }

            action.TriggerType = request.TriggerType;
            action.TriggerValue = request.TriggerValue;
            action.ActionValue = request.ActionValue;
            action.ActionType = request.ActionType;
            await _manager.SaveConfiguration(config);
            _manager.RecreateSchedule(config);
        }

        [HttpGet("flag/{flag}")]
        public async Task<bool> GetFlag([FromRoute] string flag)
        {
            return await _manager.GetFlag(flag);
        }

        [HttpGet("flag/{flag}/set")]
        public async Task SetFlag([FromRoute] string flag)
        {
            await _manager.SetFlag(flag, true);
        }

        [HttpGet("flag/{flag}/unset")]
        public async Task UnsetFlag([FromRoute] string flag)
        {
            await _manager.SetFlag(flag, false);
        }

        [HttpGet("defines")]
        public async Task<DefinitionsResponse> GetDefinitions()
        {
            var config = await _manager.GetConfiguration();
            return new DefinitionsResponse
            {
                Groups = config.Actions.Where(x => x.ActionType == FirewallActionType.AllowRouting || x.ActionType == FirewallActionType.BlockRouting).Select(x => x.ActionValue)
                    .Concat(config.KnownHosts.SelectMany(x => x.Groups ?? []))
                    .Where(x => x != null)
                    .Distinct()
                    .OrderBy(x => x).ToArray()!,
                Flags = config.Actions.Where(x => x.ActionType == FirewallActionType.SetFlag || x.ActionType == FirewallActionType.UnsetFlag).Select(x => x.ActionValue).Where(x => x != null)
                    .Distinct().OrderBy(x => x).ToDictionary(x => x, x => config.SetFlags.Contains(x))
            };
        }

        [HttpGet("process/forbidden")]
        public async Task<string[]> GetForbiddenProcesses()
        {
            return (await _manager.GetConfiguration()).ForbiddenProcessImages.ToArray();
        }


        [HttpPost("process/forbid")]
        public async Task ForbidProcess([FromBody] string name)
        {
            var config = await _manager.GetConfiguration();
            if (!config.ForbiddenProcessImages.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                config.ForbiddenProcessImages.Add(name);
                await _manager.SaveConfiguration(config);
            }
        }


        [HttpPost("process/allow")]
        public async Task AllowProcess([FromBody] string name)
        {
            var config = await _manager.GetConfiguration();
            if (config.ForbiddenProcessImages.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                config.ForbiddenProcessImages.RemoveAll(x => string.Equals(name, x, StringComparison.OrdinalIgnoreCase));
                await _manager.SaveConfiguration(config);
            }
        }

        [HttpPost("process/upload-report")]
        public async Task UploadReport([FromBody] ProcessInfo[] data)
        {
        }

        [HttpGet("state")]
        public async Task<Host[]> GetState([FromQuery] bool includeHidden = false)
        {
            var config = await _manager.GetConfiguration();
            Task<IReadOnlyList<ArpMapping>> arpMap;
            Task<IReadOnlyList<DhcpLease>> dhcpLeases;
            await Task.WhenAll(arpMap = _arpClient.GetMappingsAsync(), dhcpLeases = _dhcpLeaseReader.GetActiveLeasesAsync());
            var allHosts = new HashSet<PhysicalAddress>(config.KnownHosts.Select(x => PhysicalAddress.Parse(x.MacAddress)));
            allHosts.UnionWith(arpMap.Result.Select(x => x.EtherAddress));
            if (!includeHidden)
                allHosts.ExceptWith(config.HiddenHosts.Select(PhysicalAddress.Parse));
            return (await Task.WhenAll(allHosts.Select(async x =>
            {
                var arpMaps = arpMap.Result.Where(z => z.EtherAddress.Equals(x)).ToArray();
                var knownHost = config.KnownHosts.FirstOrDefault(z => PhysicalAddress.Parse(z.MacAddress).Equals(x));
                return new Host
                {
                    Name = knownHost?.Name ?? x.ToString(),
                    Hostname = (dhcpLeases.Result.FirstOrDefault(z => z.EtherAddress?.Equals(x) ?? false)?.ClientHostname) ??
                               arpMaps.FirstOrDefault()?.InetAddress.ToString() ?? x.ToString(),
                    MacAddress = x.ToString(),
                    Groups = knownHost?.Groups ?? [],
                    IpAddress = arpMaps.Select(z => z.InetAddress.ToString()).ToArray(),
                    IsOnline = arpMaps.Any(),
                    MacAddressInfo = await _macVendorResolver.ResolveAsync(x)
                };
            }))).OrderBy(x => x.Name).ToArray();
        }
    }
}