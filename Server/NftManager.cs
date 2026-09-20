using System.Net;
using System.Net.Sockets;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Quartz;
using Quartz.Extensibility;
using RouterNftConfig.Server.DNS;
using RouterNftConfig.Server.Models;
using RouterNftConfig.Server.NFT;

namespace RouterNftConfig.Server;

public class NftManager
{
    private readonly INftablesClient _nftablesClient;
    private readonly IScheduler _scheduler;
    private readonly string _configFile;

    public NftManager(IConfiguration config, INftablesClient nftablesClient, IScheduler scheduler)
    {
        _nftablesClient = nftablesClient;
        _scheduler = scheduler;
        _configFile = config["configFile"] ?? "config.json";
    }

    public async Task<Configuration> GetConfiguration()
    {
        if (!System.IO.File.Exists(_configFile)) return new Configuration();
        return JsonSerializer.Deserialize<Configuration>(await File.ReadAllTextAsync(_configFile), Options) ??
               new Configuration();
    }

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.General)
    {
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public async Task SaveConfiguration(Configuration config)
    {
        await System.IO.File.WriteAllTextAsync(_configFile, JsonSerializer.Serialize(config, Options));
    }

    public async Task UpdateSets()
    {
        var config = await GetConfiguration();
        var ruleset = await _nftablesClient.ListRulesetAsync();
        var groups = config.KnownHosts.SelectMany(host => (host.Groups ?? []).Select(group => (host, group))).GroupBy(x => x.group).ToArray();
        var groupNames = groups.Select(x => x.Key).ToArray();
        var batch = _nftablesClient.CreateBatch();
        foreach (var set in ruleset.Sets.Where(x => x.Name.StartsWith("fgroup_") && !groupNames.Contains(x.Name.Substring(7))))
            batch.DeleteSet(new NftSetRef(set.Family, set.Table, set.Name));
        foreach (var group in groups)
        {
            var setRef = new NftSetRef(NftFamily.Ip, "filter", "fgroup_" + group.Key);
            if (ruleset.FindSet(setRef) == null)
                batch.CreateSet(setRef, new NftSetDefinition
                {
                    Type = NftSetDataType.EtherAddress,
                    AutoMerge = false,
                    Flags = [NftSetFlag.Dynamic]
                });
            batch.ReplaceSet(setRef, group.Select(x => NftSetElement.Ether(x.host.MacAddress)));
        }

        try
        {
            await batch.ExecuteAsync();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
    }

    public async Task SetFlag(string name, bool isSet)
    {
        var config = await GetConfiguration();
        if (isSet)
        {
            if (!config.SetFlags.Contains(name))
            {
                config.SetFlags.Add(name);
                await SaveConfiguration(config);
                foreach (var action in config.Actions.Where(x => x.TriggerType == TriggerType.FlagSet && x.TriggerValue == name))
                    await RunAction(action);
            }
        }
        else
        {
            if (config.SetFlags.Remove(name))
            {
                await SaveConfiguration(config);
                foreach (var action in config.Actions.Where(x => x.TriggerType == TriggerType.FlagUnset && x.TriggerValue == name))
                    await RunAction(action);
            }
        }
    }

    public async Task RunAction(FirewallActionDefinition action)
    {
        Console.WriteLine($"Running {action}");
        switch (action.ActionType)
        {
            case FirewallActionType.SetFlag:
                await SetFlag(action.ActionValue, true);
                break;
            case FirewallActionType.UnsetFlag:
                await SetFlag(action.ActionValue, false);
                break;
            case FirewallActionType.AllowRouting:
                await AllowRouting("fgroup_" + action.ActionValue);
                break;
            case FirewallActionType.BlockRouting:
                await BlockRouting("fgroup_" + action.ActionValue);
                break;
        }
    }

    private static readonly NftChainRef ManagedChainRef = new(NftFamily.Ip, "filter", "scheduled_l2");

    private async Task AllowRouting(string setName)
    {
        var ruleset = await _nftablesClient.ListRulesetAsync();
        var chain = ruleset.FindChain(ManagedChainRef);
        var batch = _nftablesClient.CreateBatch();
        if (chain == null)
        {
            batch.CreateChain(ManagedChainRef);
            return;
        }

        var withoutDropRule = ruleset.Rules.Where(x => ManagedChainRef.Matches(x)
                                                       && !(x.Expressions.Any(z => z.TryGetProperty("drop", out _))
                                                            && x.Expressions.Any(z => z.TryGetProperty("match", out var matchElement) // 
                                                                                      && matchElement.TryGetProperty("op", out var opElement) && opElement.ValueEquals("==") //
                                                                                      && matchElement.TryGetProperty("right", out var rightElement) &&
                                                                                      rightElement.ValueEquals("@" + setName)
                                                            )
                                                           ));
        batch.ReplaceChain(ManagedChainRef, withoutDropRule);
        await batch.ExecuteAsync();
    }

    private async Task BlockRouting(string setName)
    {
        var ruleset = await _nftablesClient.ListRulesetAsync();
        var chainRef = new NftChainRef(NftFamily.Ip, "filter", "scheduled_l2");
        var chain = ruleset.FindChain(chainRef);
        var batch = _nftablesClient.CreateBatch();
        if (chain == null)
        {
            batch.CreateChain(chainRef);
            return;
        }

        var withoutDropRule =
            ruleset.Rules.Where(x => chainRef.Matches(x)
                                     && !(x.Expressions.Any(z => z.TryGetProperty("drop", out _))
                                          && x.Expressions.Any(z => z.TryGetProperty("match", out var matchElement) // 
                                                                    && matchElement.TryGetProperty("op", out var opElement) && opElement.ValueEquals("==") //
                                                                    && matchElement.TryGetProperty("right", out var rightElement) && rightElement.ValueEquals("@" + setName)
                                          )
                                         )).Select(x => new NftRuleDefinition(NftRuleTextRenderer.Render(x)));
        batch.ReplaceChain(chainRef, withoutDropRule.Append(new NftRuleDefinition($"ether saddr @{setName} drop")));
        await batch.ExecuteAsync();
    }

    public void RecreateSchedule(Configuration config)
    {
        _scheduler.Clear();
        foreach (var action in config.Actions.Where(x => x.TriggerType == TriggerType.Schedule))
        {
            _scheduler.ScheduleJob(JobBuilder.Create<RunActionJob>()
                    .WithIdentity("a_" + action.Id)
                    .UsingJobData("action", action)
                    .Build(),
                TriggerBuilder.Create()
                    .WithIdentity("t_" + action.Id)
                    .WithCronSchedule(action.TriggerValue)
                    .Build());
            Console.WriteLine($"Created {action}");
        }

        _scheduler.ScheduleJob(JobBuilder.Create<UpdateAllowedHostsJob>().WithIdentity("UpdateAllowedHostsJob").Build(),
            TriggerBuilder.Create().WithIdentity("UpdateAllowedHostsJobTrigger").WithSimpleSchedule(TimeSpan.FromHours(1)).Build());
        _scheduler.ScheduleJob(JobBuilder.Create<UpdateDoHsJob>().WithIdentity("UpdateDoHsJobJob").Build(),
            TriggerBuilder.Create().WithIdentity("UpdateDoHsJobTrigger").WithSimpleSchedule(TimeSpan.FromDays(1)).Build());
        
    }

    public async Task Startup()
    {
        var config = await GetConfiguration();
        await UpdateSets();
        RecreateSchedule(config);
        await CreateDynamicAllowSet();
        new DnstapListener().Startup((host, addr, ttl) =>
        {
            if (host == "whatsapp.com" || host == "whatsapp.net" || host.EndsWith(".whatsapp.com") || host.EndsWith(".whatsapp.net"))
            {
                if (addr.AddressFamily != AddressFamily.InterNetwork) return;
                _nftablesClient.CreateBatch().AddSetElement(DynamicAllowSetRef, NftSetElement.Raw($"{addr.ToString()} timeout {ttl}s")).ExecuteAsync().Wait();
                Console.WriteLine($"Updated dynamic allowed set with {host} -> {addr}");
            }
        });

        var nowUtc = DateTimeOffset.UtcNow;
        var localNow = TimeZoneInfo.ConvertTime(nowUtc, TimeZoneInfo.Local);
        var today = localNow.Date;
        var todayStartUtc = new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(today, DateTimeKind.Unspecified), TimeZoneInfo.Local), TimeSpan.Zero);
        var jobKeys = await _scheduler.GetJobKeys(GroupMatcher<JobKey>.AnyGroup());
        var toRun = new List<ScheduledJob>();
        foreach (var jobKey in jobKeys)
        {
            if (jobKey.Name.Contains("UpdateAllowedHostsJob") || jobKey.Name.Contains("UpdateDoHsJob")) continue;
            var triggers = await _scheduler.GetTriggersOfJob(jobKey);
            ScheduledJob? latest = null;
            foreach (var trigger in triggers)
            {
                var fireTime = await FindLastFireTime(_scheduler, trigger, todayStartUtc, nowUtc);
                if (fireTime == null) continue;

                if (latest == null || fireTime > latest.FireTimeUtc || (fireTime == latest.FireTimeUtc && trigger.Priority > latest.Priority))
                    latest = new ScheduledJob(jobKey, trigger.Key, fireTime.Value, trigger.Priority);
            }

            if (latest != null)
                toRun.Add(latest);
        }

        foreach (var job in toRun
                     .OrderBy(x => x.FireTimeUtc)
                     .ThenByDescending(x => x.Priority))
        {
            await _scheduler.TriggerJob(job.JobKey);
        }
    }

    private static readonly NftSetRef DynamicAllowSetRef = new NftSetRef(NftFamily.Ip, "filter", "allowed_dynamic");
    private async Task CreateDynamicAllowSet()
    {
        var ruleset = await _nftablesClient.ListRulesetAsync();
        var batch = _nftablesClient.CreateBatch();
        if (ruleset.FindSet(DynamicAllowSetRef) == null)
            batch.CreateSet(DynamicAllowSetRef, new NftSetDefinition
            {
                Type = NftSetDataType.IPv4Address,
                Flags = [NftSetFlag.Timeout]
            });
        if (!ruleset.Rules.Any(x => ManagedChainRef.Matches(x) &&
                                    (x.Expressions.Any(z => z.TryGetProperty("return", out _))
                                     && x.Expressions.Any(z => z.TryGetProperty("match", out var matchElement) // 
                                                               && matchElement.TryGetProperty("op", out var opElement) && opElement.ValueEquals("==") //
                                                               && matchElement.TryGetProperty("right", out var rightElement) && rightElement.ValueEquals("@allowed_dynamic")
                                     )
                                    )
            ))
        {
            var rules = ruleset.Rules.Where(x => ManagedChainRef.Matches(x)).Select(NftRuleTextRenderer.Render).ToList();
            rules.Insert(0, $"ip daddr @allowed_dynamic return");
            batch.ReplaceChain(ManagedChainRef, rules.Select(x => new NftRuleDefinition(x)));
        }

        await batch.ExecuteAsync();
    }

    private static async Task<DateTimeOffset?> FindLastFireTime(IScheduler scheduler, ITrigger trigger, DateTimeOffset fromUtc, DateTimeOffset toUtc)
    {
        ICalendar? calendar = null;
        var probe = (IMutableTrigger)trigger.Clone();
        if (probe.StartTimeUtc > fromUtc)
            probe.StartTimeUtc = fromUtc;

        if (probe.CalendarName != null)
            calendar = await scheduler.GetCalendar(probe.CalendarName);

        DateTimeOffset? last = null;
        var cursor = fromUtc.AddTicks(-1);
        while (true)
        {
            var next = probe.GetFireTimeAfter(cursor);
            if (next is null || next > toUtc)
                return last;
            if (calendar is null || calendar.IsTimeIncluded(next.Value))
                last = next;
            cursor = next.Value;
        }
    }

    private sealed record ScheduledJob(JobKey JobKey, TriggerKey TriggerKey, DateTimeOffset FireTimeUtc, int Priority);

    public static SemaphoreSlim NftOperationLock = new SemaphoreSlim(1, 1);

    public async Task UpdateAllowedSet()
    {
        var config = await GetConfiguration();
        var ruleset = await _nftablesClient.ListRulesetAsync();
        var setRef = new NftSetRef(NftFamily.Ip, "filter", "allowed_targets");
        var batch = _nftablesClient.CreateBatch();
        
        if (ruleset.FindSet(setRef) == null)
            batch.CreateSet(setRef, new NftSetDefinition
            {
                Type = NftSetDataType.IPv4Address
            });
        
        if (!ruleset.Rules.Any(x => ManagedChainRef.Matches(x) &&
                                    (x.Expressions.Any(z => z.TryGetProperty("return", out _))
                                     && x.Expressions.Any(z => z.TryGetProperty("match", out var matchElement) // 
                                                               && matchElement.TryGetProperty("op", out var opElement) && opElement.ValueEquals("==") //
                                                               && matchElement.TryGetProperty("right", out var rightElement) && rightElement.ValueEquals("@allowed_targets")
                                     )
                                    )
            ))
        {
            var rules = ruleset.Rules.Where(x => ManagedChainRef.Matches(x)).Select(NftRuleTextRenderer.Render).ToList();
            rules.Insert(0, $"ip daddr @allowed_targets return");
            batch.ReplaceChain(ManagedChainRef, rules.Select(x => new NftRuleDefinition(x)));
        }
        
        var allIps = new HashSet<IPAddress>();
        foreach (var host in config.AlwaysAllowedTargets ?? [])
        {
            allIps.UnionWith((await Dns.GetHostAddressesAsync(host)).Where(x => x.AddressFamily == AddressFamily.InterNetwork));
        }

        batch.ReplaceSet(setRef, allIps.Select(x => NftSetElement.Inet(x.ToString())));
        Console.WriteLine($"Updated statically resolved allowed set with {allIps.Count} IPs");
        await batch.ExecuteAsync();
    }

    private static HttpClient HttpClient = new HttpClient();
    public async Task UpdateDoHsSet()
    {
        var ruleset = await _nftablesClient.ListRulesetAsync();
        var setRef = new NftSetRef(NftFamily.Ip, "filter", "dohs");
        var batch = _nftablesClient.CreateBatch();
        
        if (ruleset.FindSet(setRef) == null)
            batch.CreateSet(setRef, new NftSetDefinition
            {
                Type = NftSetDataType.IPv4Address,
                AutoMerge = true,
                Flags = [NftSetFlag.Interval]
            });
        
        if (!ruleset.Rules.Any(x => ManagedChainRef.Matches(x) &&
                                    (x.Expressions.Any(z => z.TryGetProperty("drop", out _))
                                     && x.Expressions.Any(z => z.TryGetProperty("match", out var matchElement) // 
                                                               && matchElement.TryGetProperty("op", out var opElement) && opElement.ValueEquals("==") //
                                                               && matchElement.TryGetProperty("right", out var rightElement) && rightElement.ValueEquals("@dohs")
                                     )
                                    )
            ))
        {
            var rules = ruleset.Rules.Where(x => ManagedChainRef.Matches(x)).Select(NftRuleTextRenderer.Render).ToList();
            rules.Insert(0, $"ip daddr @dohs drop");
            batch.ReplaceChain(ManagedChainRef, rules.Select(x => new NftRuleDefinition(x)));
        }

        var allIps = new HashSet<string>((await HttpClient.GetStringAsync("https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-ipv4.txt")).Split("\n")
            .Select(x => x.Split([' ', '\t', '#'], 2)[0].Trim())
            .Where(x => !string.IsNullOrEmpty(x))
            .Select(x => IPAddress.TryParse(x, out var ip) ? ip : null)
            .Where(x => x != null)
            .Select(x=>x.ToString()));
        await batch.ReplaceSet(setRef, []).ExecuteAsync();
        batch = _nftablesClient.CreateBatch();
        batch.ReplaceSet(setRef, allIps.Select(x => NftSetElement.Inet(x.ToString())));
        Console.WriteLine($"Updated DoHs set with {allIps.Count} IPs");

        await batch.ExecuteAsync();
    }
}