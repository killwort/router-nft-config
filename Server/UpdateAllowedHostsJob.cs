using Quartz;

namespace RouterNftConfig.Server;

public class UpdateAllowedHostsJob : IJob
{
    private readonly NftManager _manager;

    public UpdateAllowedHostsJob(NftManager manager)
    {
        _manager = manager;
    }
    public async ValueTask Execute(IJobExecutionContext context, CancellationToken cancellationToken = new CancellationToken())
    {
        await NftManager.NftOperationLock.WaitAsync(cancellationToken);
        try
        {
            await _manager.UpdateAllowedSet();
        }
        finally
        {
            NftManager.NftOperationLock.Release();
        }
    }
}