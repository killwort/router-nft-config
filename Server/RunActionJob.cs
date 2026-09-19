using Quartz;
using RouterNftConfig.Server.Models;

namespace RouterNftConfig.Server;

public class RunActionJob : IJob
{
    private readonly NftManager _manager;

    public RunActionJob(NftManager manager)
    {
        _manager = manager;
    }

    public async ValueTask Execute(IJobExecutionContext context, CancellationToken cancellationToken = new CancellationToken())
    {
        await _manager.RunAction((FirewallActionDefinition)context.MergedJobDataMap["action"]!);
    }
}