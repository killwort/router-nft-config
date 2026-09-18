using System.Threading;
using System.Threading.Tasks;
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
        var action = (FirewallActionDefinition)context.MergedJobDataMap["action"];
        switch (action.Action)
        {
            case FirewallActionType.AddFlag:
                _manager.SetFlag(action.Flag, true);
                break;
            case FirewallActionType.RemoveFlag:
                _manager.SetFlag(action.Flag, false);
                break;
        }
    }
}