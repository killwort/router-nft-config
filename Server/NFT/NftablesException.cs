namespace RouterNftConfig.Server.NFT;

public sealed class NftablesException : Exception
{
    public NftablesException(
        string message,
        int? exitCode = null,
        string? standardError = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        ExitCode = exitCode;
        StandardError = standardError;
    }

    public int? ExitCode { get; }
    public string? StandardError { get; }
}