using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using RouterNftConfig.Server.ARP;
using RouterNftConfig.Server.DHCP;
using RouterNftConfig.Server.MACPrefixes;
using RouterNftConfig.Server.Models;
using RouterNftConfig.Server.NFT;

namespace RouterNftConfig.Server
{
    [Route("api")]
    public class ApiController : Controller
    {
        private readonly INftablesClient _nftablesClient;
        private readonly IArpClient _arpClient;
        private readonly IDhcpLeaseReader _dhcpLeaseReader;
        private readonly IMacVendorResolver _macVendorResolver;
        private readonly string _configFile;

        public ApiController(INftablesClient nftablesClient, IArpClient arpClient, IDhcpLeaseReader dhcpLeaseReader, IMacVendorResolver macVendorResolver, IConfiguration config)
        {
            _nftablesClient = nftablesClient;
            _arpClient = arpClient;
            _dhcpLeaseReader = dhcpLeaseReader;
            _macVendorResolver = macVendorResolver;
            _configFile = config["configFile"] ?? "config.json";
        }

        private async Task<Configuration> GetConfiguration()
        {
            if (!System.IO.File.Exists(_configFile)) return new Configuration();
            return System.Text.Json.JsonSerializer.Deserialize<Configuration>(await System.IO.File.ReadAllTextAsync(_configFile), Options) ??
                   new Configuration();
        }

        private static readonly JsonSerializerOptions Options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() },
            WriteIndented = true
        };

        private async Task SaveConfiguration(Configuration config)
        {
            await System.IO.File.WriteAllTextAsync(_configFile, System.Text.Json.JsonSerializer.Serialize(config, Options));
        }

        [HttpGet("hide/{mac}")]
        public async Task HideHost([FromRoute] string mac)
        {
            var config = await GetConfiguration();
            config.HiddenHosts.Add(PhysicalAddress.Parse(mac).ToString());
            await SaveConfiguration(config);
        }

        [HttpGet("unhide/{mac}")]
        public async Task UnhideHost([FromRoute] string mac)
        {
            var config = await GetConfiguration();
            config.HiddenHosts.Remove(PhysicalAddress.Parse(mac).ToString());
            await SaveConfiguration(config);
        }

        [HttpPost]
        public async Task UpdateHost([FromBody] UpdateHostRequest request)
        {
            var config = await GetConfiguration();
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
            await SaveConfiguration(config);
        }

        [HttpPost("action")]
        public async Task UpdateAction([FromBody]UpdateActionRequest request)
        {
            var config = await GetConfiguration();
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
            action.Action = request.Action;
            action.Group = request.Group;
            action.Flag = request.Flag;
            await SaveConfiguration(config);
        }

        [HttpGet("defines")]
        public async Task<DefinitionsResponse> GetDefinitions()
        {
            var config = await GetConfiguration();
            return new DefinitionsResponse
            {
                Groups = config.Actions.Select(x => x.Group)
                    .Concat(config.KnownHosts.SelectMany(x => x.Groups ?? []))
                    .Where(x => x != null)
                    .Distinct()
                    .OrderBy(x => x).ToArray()!,
                Flags = config.Actions.Select(x => x.Flag).Where(x => x != null).Distinct().OrderBy(x => x).ToArray()!
            };
        }

        [HttpGet("state")]
        public async Task<Host[]> GetState([FromQuery] bool includeHidden = false)
        {
            var config = await GetConfiguration();
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