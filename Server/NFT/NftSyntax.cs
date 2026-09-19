using System.Text;

namespace RouterNftConfig.Server.NFT;

internal static class NftSyntax
{
    public static string Identifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.IndexOfAny(['\r', '\n', ' ', '\t']) >= 0)
            throw new ArgumentException("An identifier must fit on one line and not contain whitespace.", nameof(value));
        return value;
    }

    public static string StringLiteral(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.IndexOfAny(['\r', '\n']) >= 0)
            throw new ArgumentException("A string literal must fit on one line.", nameof(value));
        return Quote(value);
    }

    private static string Quote(string value)
    {
        var escaped = new StringBuilder(value.Length + 2).Append('"');
        foreach (var ch in value)
        {
            if (ch is '\\' or '"') escaped.Append('\\');
            escaped.Append(ch);
        }
        return escaped.Append('"').ToString();
    }
}