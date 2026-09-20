using System.Text;

namespace RouterNftConfig.Server.NFT;

/// <summary>Options used when creating a regular or base chain.</summary>
public sealed record NftChainDefinition
{
    public NftChainType? Type { get; init; }
    public NftChainHook? Hook { get; init; }
    public int? Priority { get; init; }
    public NftChainPolicy? Policy { get; init; }
    public string? Device { get; init; }
    public string? Comment { get; init; }

    internal void Validate()
    {
        var basePropertyCount = (Type is null ? 0 : 1) + (Hook is null ? 0 : 1) +
            (Priority is null ? 0 : 1);
        if (basePropertyCount is not 0 and not 3)
            throw new ArgumentException(
                "Type, Hook and Priority must either all be supplied for a base chain or all omitted.");
        if (basePropertyCount == 0 && Policy is not null)
            throw new ArgumentException("Policy is only valid for a base chain.", nameof(Policy));
        if (basePropertyCount == 0 && Device is not null)
            throw new ArgumentException("Device is only valid for a base chain.", nameof(Device));
        if (Device?.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("A device name must fit on one line.", nameof(Device));
        if (Comment?.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("A comment must fit on one line.", nameof(Comment));
    }

    internal string? ToNftBody()
    {
        Validate();
        if (Type is null && string.IsNullOrWhiteSpace(Comment)) return null;

        var result = new StringBuilder("{");
        if (Type is { } type)
        {
            result.Append(" type ").Append(type.ToNftString())
                .Append(" hook ").Append(Hook!.Value.ToNftString());
            if (!string.IsNullOrWhiteSpace(Device))
                result.Append(" device ").Append(NftSyntax.StringLiteral(Device));
            result.Append(" priority ").Append(Priority!.Value).Append(';');
            if (Policy is { } policy)
                result.Append(" policy ").Append(policy.ToNftString()).Append(';');
        }
        if (!string.IsNullOrWhiteSpace(Comment))
            result.Append(" comment ").Append(NftSyntax.StringLiteral(Comment)).Append(';');
        return result.Append(" }").ToString();
    }

}