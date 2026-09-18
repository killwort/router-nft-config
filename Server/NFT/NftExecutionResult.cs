namespace RouterNftConfig.Server.NFT;

public sealed record NftExecutionResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool IsSimulated = false,
    bool StateChanged = true);