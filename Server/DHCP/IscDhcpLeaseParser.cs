using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace RouterNftConfig.Server.DHCP;

internal static class IscDhcpLeaseParser
{
    public static IReadOnlyList<DhcpLease> ParseLatest(string contents)
    {
        ArgumentNullException.ThrowIfNull(contents);
        var tokens = Tokenize(contents);
        var latest = new Dictionary<IPAddress, DhcpLease>();
        var depth = 0;

        for (var i = 0; i < tokens.Count; i++)
        {
            if (tokens[i] == "{") { depth++; continue; }
            if (tokens[i] == "}") { if (depth > 0) depth--; continue; }
            if (depth != 0 || tokens[i] != "lease" || i + 2 >= tokens.Count) continue;
            if (!IPAddress.TryParse(tokens[i + 1], out var address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                tokens[i + 2] != "{")
                continue;

            var closingBrace = FindClosingBrace(tokens, i + 2);
            if (closingBrace < 0) break; // dhcpd may be appending the final declaration

            var lease = ParseLease(address, tokens, i + 3, closingBrace);
            latest[address] = lease;
            i = closingBrace;
        }

        return latest.Values.ToArray();
    }

    private static DhcpLease ParseLease(
        IPAddress address,
        IReadOnlyList<string> tokens,
        int start,
        int end)
    {
        DateTimeOffset? starts = null;
        DateTimeOffset? ends = null;
        var neverExpires = false;
        PhysicalAddress? ether = null;
        string? hostname = null;
        var bindingState = string.Empty;
        var nestedDepth = 0;

        for (var i = start; i < end; i++)
        {
            if (tokens[i] == "{") { nestedDepth++; continue; }
            if (tokens[i] == "}") { if (nestedDepth > 0) nestedDepth--; continue; }
            if (nestedDepth != 0) continue;

            switch (tokens[i])
            {
                case "starts":
                {
                    var value = ParseDate(tokens, i + 1, end);
                    starts = value.Value;
                    i = SkipStatement(tokens, i, end);
                    break;
                }
                case "ends":
                {
                    var value = ParseDate(tokens, i + 1, end);
                    ends = value.Value;
                    neverExpires = value.IsNever;
                    i = SkipStatement(tokens, i, end);
                    break;
                }
                case "binding" when i + 2 < end && tokens[i + 1] == "state":
                    bindingState = tokens[i + 2];
                    i = SkipStatement(tokens, i, end);
                    break;
                case "hardware" when i + 2 < end && tokens[i + 1] == "ethernet":
                    ether = TryParseEther(tokens[i + 2]);
                    i = SkipStatement(tokens, i, end);
                    break;
                case "client-hostname" when i + 1 < end:
                    hostname = tokens[i + 1];
                    i = SkipStatement(tokens, i, end);
                    break;
            }
        }

        return new DhcpLease(
            address,
            ether,
            hostname,
            starts,
            ends,
            neverExpires,
            bindingState);
    }

    private static LeaseDate ParseDate(IReadOnlyList<string> tokens, int start, int end)
    {
        if (start >= end) return default;
        if (tokens[start] == "never") return new LeaseDate(null, IsNever: true);
        if (tokens[start] == "epoch" && start + 1 < end &&
            long.TryParse(tokens[start + 1], out var seconds))
        {
            try { return new LeaseDate(DateTimeOffset.FromUnixTimeSeconds(seconds), IsNever: false); }
            catch (ArgumentOutOfRangeException) { return default; }
        }

        // Default ISC format: weekday yyyy/MM/dd HH:mm:ss (weekday is ignored by dhcpd too).
        if (start + 2 < end &&
            DateTimeOffset.TryParseExact(
                $"{tokens[start + 1]} {tokens[start + 2]}",
                "yyyy/MM/dd HH:mm:ss",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal |
                System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var value))
            return new LeaseDate(value, IsNever: false);

        return default;
    }

    private static int SkipStatement(IReadOnlyList<string> tokens, int start, int end)
    {
        for (var i = start; i < end; i++)
            if (tokens[i] == ";") return i;
        return end - 1;
    }

    private static int FindClosingBrace(IReadOnlyList<string> tokens, int openingBrace)
    {
        var depth = 0;
        for (var i = openingBrace; i < tokens.Count; i++)
        {
            if (tokens[i] == "{") depth++;
            else if (tokens[i] == "}" && --depth == 0) return i;
        }
        return -1;
    }

    private static PhysicalAddress? TryParseEther(string value)
    {
        var compact = value.Replace(":", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);
        if (compact.Length != 12 || !compact.All(Uri.IsHexDigit)) return null;
        var address = PhysicalAddress.Parse(compact);
        return address.GetAddressBytes().Length == 6 ? address : null;
    }

    private static IReadOnlyList<string> Tokenize(string value)
    {
        var result = new List<string>();
        for (var i = 0; i < value.Length;)
        {
            if (char.IsWhiteSpace(value[i])) { i++; continue; }
            if (value[i] == '#')
            {
                while (i < value.Length && value[i] != '\n') i++;
                continue;
            }
            if (value[i] is '{' or '}' or ';')
            {
                result.Add(value[i++].ToString());
                continue;
            }
            if (value[i] == '"')
            {
                result.Add(ReadQuoted(value, ref i));
                continue;
            }

            var start = i;
            while (i < value.Length && !char.IsWhiteSpace(value[i]) &&
                   value[i] is not ('{' or '}' or ';' or '#' or '"'))
                i++;
            if (i > start) result.Add(value[start..i]);
        }
        return result;
    }

    private static string ReadQuoted(string value, ref int index)
    {
        index++; // opening quote
        var result = new StringBuilder();
        while (index < value.Length)
        {
            var ch = value[index++];
            if (ch == '"') break;
            if (ch != '\\' || index >= value.Length)
            {
                result.Append(ch);
                continue;
            }

            if (index + 2 < value.Length && IsOctal(value[index]) &&
                IsOctal(value[index + 1]) && IsOctal(value[index + 2]))
            {
                var octal = (value[index] - '0') * 64 +
                    (value[index + 1] - '0') * 8 + value[index + 2] - '0';
                result.Append((char)octal);
                index += 3;
            }
            else
            {
                result.Append(value[index++]);
            }
        }
        return result.ToString();
    }

    private static bool IsOctal(char value) => value is >= '0' and <= '7';

    private readonly record struct LeaseDate(DateTimeOffset? Value, bool IsNever);
}