using Quartz;

namespace RouterNftConfig.Server;

public class UpdateDoHsJob : IJob
{
    private readonly NftManager _manager;

    public UpdateDoHsJob(NftManager manager)
    {
        _manager = manager;
    }
    public async ValueTask Execute(IJobExecutionContext context, CancellationToken cancellationToken = new CancellationToken())
    {
        await NftManager.NftOperationLock.WaitAsync(cancellationToken);
        try
        {
            await _manager.UpdateDoHsSet();
        }
        finally
        {
            NftManager.NftOperationLock.Release();
        }
    }
}