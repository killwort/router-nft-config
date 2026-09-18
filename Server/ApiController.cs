using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Quartz;
using RouterNftConfig.Server.ARP;
using RouterNftConfig.Server.DHCP;
using RouterNftConfig.Server.MACPrefixes;
using RouterNftConfig.Server.Models;

namespace RouterNftConfig.Server
{
    [Route("api")]
    public class ApiController : Controller
    {
        private readonly NftManager _manager;
        private readonly IArpClient _arpClient;
        private readonly IDhcpLeaseReader _dhcpLeaseReader;
        private readonly IMacVendorResolver _macVendorResolver;
        private readonly IScheduler _scheduler;

        public ApiController(NftManager manager, IArpClient arpClient, IDhcpLeaseReader dhcpLeaseReader, IMacVendorResolver macVendorResolver, IConfiguration config, IScheduler scheduler)
        {
            _manager = manager;
            _arpClient = arpClient;
            _dhcpLeaseReader = dhcpLeaseReader;
            _macVendorResolver = macVendorResolver;
            _scheduler = scheduler;
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
        }

        [HttpPost("action")]
        public async Task UpdateAction([FromBody]UpdateActionRequest request)
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
            action.Action = request.Action;
            action.Group = request.Group;
            action.Flag = request.Flag;
            await _manager.SaveConfiguration(config);
            CreateSchedule(config);
        }

        private void CreateSchedule(Configuration config)
        {
            _scheduler.Clear();
            foreach (var action in config.Actions.Where(x=>x.TriggerType==TriggerType.Schedule))
            {
                _scheduler.ScheduleJob(JobBuilder.Create<RunActionJob>()
                        .UsingJobData("action", action)
                        .Build(),
                    TriggerBuilder.Create()
                        .WithCronSchedule(action.TriggerValue)
                        .Build());
            }
        }


        [HttpGet("defines")]
        public async Task<DefinitionsResponse> GetDefinitions()
        {
            var config = await _manager.GetConfiguration();
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