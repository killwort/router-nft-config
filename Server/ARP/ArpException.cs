namespace RouterNftConfig.Server.ARP;

public sealed class ArpException : Exception
{
    public ArpException(
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