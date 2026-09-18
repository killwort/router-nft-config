using System;
using System.Text;

namespace RouterNftConfig.Server.NFT;

internal static class NftSyntax
{
    public static string Identifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var escaped = new StringBuilder(value.Length + 2).Append('"');
        foreach (var ch in value)
        {
            if (ch is '\\' or '"') escaped.Append('\\');
            escaped.Append(ch);
        }
        return escaped.Append('"').ToString();
    }
}