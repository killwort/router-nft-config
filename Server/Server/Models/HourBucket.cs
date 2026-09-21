namespace RouterNftConfig.Server.Models;

public sealed class HourBucket
{
    public DateTime Hour { get; set; }

    public HashSet<string> Processes { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}