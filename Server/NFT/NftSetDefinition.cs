using System.Text;

namespace RouterNftConfig.Server.NFT;

/// <summary>Options used when creating a named nftables set.</summary>
public sealed record NftSetDefinition
{
    public required NftSetDataType Type { get; init; }
    public IReadOnlyCollection<NftSetFlag> Flags { get; init; } = [];
    public TimeSpan? Timeout { get; init; }
    public TimeSpan? GarbageCollectionInterval { get; init; }
    public int? Size { get; init; }
    public NftSetPolicy? Policy { get; init; }
    public bool AutoMerge { get; init; }
    public string? Comment { get; init; }
    public IReadOnlyCollection<NftSetElement> InitialElements { get; init; } = [];

    internal string ToNftBody()
    {
        Validate();
        var result = new StringBuilder("{ type ").Append(Type.ToNftString()).Append(';');
        var flags = EffectiveFlags();
        if (flags.Count > 0)
            result.Append(" flags ").Append(string.Join(',', flags.Select(x => x.ToNftString())))
                .Append(';');
        if (Timeout is { } timeout)
            result.Append(" timeout ").Append(ToWholeSeconds(timeout, nameof(Timeout))).Append("s;");
        if (GarbageCollectionInterval is { } gcInterval)
            result.Append(" gc-interval ")
                .Append(ToWholeSeconds(gcInterval, nameof(GarbageCollectionInterval))).Append("s;");
        if (Size is { } size) result.Append(" size ").Append(size).Append(';');
        if (Policy is { } policy) result.Append(" policy ").Append(policy.ToNftString()).Append(';');
        if (AutoMerge) result.Append(" auto-merge;");
        if (!string.IsNullOrWhiteSpace(Comment))
            result.Append(" comment ").Append(NftSyntax.StringLiteral(Comment)).Append(';');
        if (InitialElements.Count > 0)
            result.Append(" elements = { ")
                .Append(string.Join(", ", InitialElements.Select(x => x.ToNftLiteral())))
                .Append(" };");
        return result.Append(" }").ToString();
    }

    internal IReadOnlyList<NftSetFlag> EffectiveFlags()
    {
        var flags = Flags.ToHashSet();
        if (Timeout is not null || GarbageCollectionInterval is not null)
            flags.Add(NftSetFlag.Timeout);
        return flags.OrderBy(x => x).ToArray();
    }

    internal void Validate()
    {
        ArgumentNullException.ThrowIfNull(Flags);
        ArgumentNullException.ThrowIfNull(InitialElements);
        if (InitialElements.Any(element => element is null))
            throw new ArgumentException(
                "Initial elements cannot contain null.", nameof(InitialElements));
        if (Size is <= 0) throw new ArgumentOutOfRangeException(nameof(Size), "Size must be positive.");
        if (Timeout is { } timeout) _ = ToWholeSeconds(timeout, nameof(Timeout));
        if (GarbageCollectionInterval is { } gcInterval)
            _ = ToWholeSeconds(gcInterval, nameof(GarbageCollectionInterval));
        if (AutoMerge && !Flags.Contains(NftSetFlag.Interval))
            throw new ArgumentException("AutoMerge requires the Interval flag.", nameof(AutoMerge));
        if (Comment?.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("A comment must fit on one line.", nameof(Comment));
    }

    internal static long ToWholeSeconds(TimeSpan value, string parameterName)
    {
        if (value <= TimeSpan.Zero || value.Ticks % TimeSpan.TicksPerSecond != 0)
            throw new ArgumentOutOfRangeException(
                parameterName, "The duration must be positive and contain a whole number of seconds.");
        return checked(value.Ticks / TimeSpan.TicksPerSecond);
    }
}