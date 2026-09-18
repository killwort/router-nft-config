using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace RouterNftConfig.Server.NFT;

/// <summary>A typed set value. Use the factories to get validation and canonical formatting.</summary>
public abstract record NftSetElement
{
    private NftSetElement() { }

    public abstract string Value { get; }
    internal abstract string ToNftLiteral();

    public static NftSetElement Ether(string macAddress) => new EtherAddress(macAddress);
    public static NftSetElement Inet(string ipAddress) => new InternetAddress(ipAddress);

    /// <summary>
    /// An advanced raw nft set expression, for example an interval or a value with timeout.
    /// The caller is responsible for its safety and validity.
    /// </summary>
    public static NftSetElement Raw(string expression) => new RawExpression(expression);

    private sealed record EtherAddress : NftSetElement
    {
        public EtherAddress(string value)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value);
            var compact = value.Replace(":", string.Empty, StringComparison.Ordinal)
                .Replace("-", string.Empty, StringComparison.Ordinal);
            if (compact.Length != 12 || !compact.All(Uri.IsHexDigit))
                throw new FormatException($"Invalid Ethernet address '{value}'.");

            var parsed = PhysicalAddress.Parse(compact).GetAddressBytes();
            Value = string.Join(":", parsed.Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));
        }

        public override string Value { get; }
        internal override string ToNftLiteral() => Value;
    }

    private sealed record InternetAddress : NftSetElement
    {
        public InternetAddress(string value)
        {
            if (!IPAddress.TryParse(value, out var address))
                throw new FormatException($"Invalid IP address '{value}'.");
            Value = address.ToString();
        }

        public override string Value { get; }
        internal override string ToNftLiteral() => Value;
    }

    private sealed record RawExpression : NftSetElement
    {
        public RawExpression(string value)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(value);
            if (value.IndexOfAny(['\r', '\n']) >= 0)
                throw new ArgumentException("A set expression must fit on one line.", nameof(value));
            Value = value;
        }

        public override string Value { get; }
        internal override string ToNftLiteral() => Value;
    }
}