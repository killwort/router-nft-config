using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;

namespace RouterNftConfig.Server.NFT;

/// <summary>Renders rules returned by nft's JSON ruleset listing into native nft syntax.</summary>
public static class NftRuleTextRenderer
{
    public static string Render(NftRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        return Render(rule.Expressions, rule.Comment, rule.MockExpression);
    }

    public static string RenderExpression(JsonElement expression) =>
        new Renderer().Expression(expression);

    public static string RenderStatement(JsonElement statement) =>
        new Renderer().Statement(statement);

    internal static string Render(
        IReadOnlyList<JsonElement> expressions,
        string? comment,
        string? mockExpression = null)
    {
        ArgumentNullException.ThrowIfNull(expressions);
        if (expressions.Count == 0)
        {
            if (string.IsNullOrWhiteSpace(mockExpression))
                throw new NftRuleRenderingException("An nft rule must contain at least one statement.");
            return AppendComment(mockExpression, comment);
        }

        var renderer = new Renderer();
        var result = string.Join(' ', expressions.Select(renderer.Statement));
        return AppendComment(result, comment);
    }

    private static string AppendComment(string expression, string? comment) =>
        string.IsNullOrWhiteSpace(comment)
            ? expression
            : expression + " comment " + NftSyntax.StringLiteral(comment);

    private sealed class Renderer
    {
        internal string Statement(JsonElement statement)
        {
            var (name, value) = SingleProperty(statement, "statement");
            return name switch
            {
                "accept" or "drop" or "continue" or "return" => name,
                "jump" or "goto" => RenderJump(name, value),
                "match" => RenderMatch(value),
                "counter" => RenderCounter(value),
                "mangle" => $"{Expression(Required(value, "key"))} set " +
                    Expression(Required(value, "value")),
                "quota" => RenderQuota(value),
                "limit" => RenderLimit(value),
                "fwd" => RenderFwd(value),
                "notrack" => "notrack",
                "dup" => RenderDup(value),
                "snat" or "dnat" or "masquerade" or "redirect" => RenderNat(name, value),
                "reject" => RenderReject(value),
                "set" => RenderDynamicSet(value),
                "log" => RenderLog(value),
                "ct helper" or "ct timeout" or "ct expectation" =>
                    $"{name} set {Expression(value)}",
                "meter" => RenderMeter(value),
                "queue" => RenderQueue(value),
                "vmap" => $"{Expression(Required(value, "key"))} vmap " +
                    Expression(Required(value, "data")),
                "ct count" => RenderCtCount(value),
                "xt" => throw Unsupported(
                    "xt compatibility statements cannot be restored by native nft", statement),
                _ => throw Unsupported($"unsupported nft JSON statement '{name}'", statement)
            };
        }

        internal string Expression(JsonElement expression)
        {
            return expression.ValueKind switch
            {
                JsonValueKind.String => RenderImmediate(expression.GetString()!),
                JsonValueKind.Number => expression.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Array => RenderSetItems(expression),
                JsonValueKind.Object => RenderObjectExpression(expression),
                _ => throw Unsupported("unsupported nft JSON expression", expression)
            };
        }

        private string RenderObjectExpression(JsonElement expression)
        {
            var (name, value) = SingleProperty(expression, "expression");
            return name switch
            {
                "concat" => string.Join(" . ", Array(value).Select(Expression)),
                "set" => RenderSet(value),
                "map" => $"{Expression(Required(value, "key"))} map " +
                    Expression(Required(value, "data")),
                "prefix" => $"{Expression(Required(value, "addr"))}/" +
                    RequiredInt64(value, "len"),
                "range" => RenderRange(value),
                "payload" => RenderPayload(value),
                "exthdr" => RenderNamedField(string.Empty, value, includeOffset: true),
                "tcp option" => RenderNamedField("tcp option", value),
                "sctp chunk" => RenderNamedField("sctp chunk", value),
                "dccp option" => $"dccp option {RequiredInt64(value, "type")}",
                "meta" => $"meta {RequiredString(value, "key")}",
                "rt" => RenderRt(value),
                "ct" => RenderCt(value),
                "numgen" => RenderNumgen(value),
                "jhash" => RenderJhash(value),
                "symhash" => RenderSymhash(value),
                "fib" => RenderFib(value),
                "|" or "^" or "&" or "<<" or ">>" => RenderBinary(name, value),
                "accept" or "drop" or "continue" or "return" => name,
                "jump" or "goto" => RenderJump(name, value),
                "elem" => RenderElement(value),
                "socket" => $"socket {RequiredString(value, "key")}",
                "osf" => RenderOsf(value),
                _ => throw Unsupported($"unsupported nft JSON expression '{name}'", expression)
            };
        }

        private string RenderMatch(JsonElement match)
        {
            var leftElement = Required(match, "left");
            var rightElement = Required(match, "right");
            var left = Expression(leftElement);
            var right = Expression(rightElement);
            var operation = RequiredString(match, "op");

            if ((operation is "==" or "in") && IsSetLike(rightElement))
                return $"{left} {right}";
            if ((rightElement.ValueKind is JsonValueKind.True or JsonValueKind.False) &&
                IsExistenceExpression(leftElement))
                return $"{left} {(rightElement.GetBoolean() ? "exists" : "missing")}";
            return $"{left} {operation} {right}";
        }

        private static bool IsSetLike(JsonElement expression)
        {
            if (expression.ValueKind == JsonValueKind.Array) return true;
            if (expression.ValueKind == JsonValueKind.String)
                return expression.GetString()!.StartsWith('@');
            return expression.ValueKind == JsonValueKind.Object &&
                expression.EnumerateObject().FirstOrDefault().Name == "set";
        }

        private static bool IsExistenceExpression(JsonElement expression)
        {
            if (expression.ValueKind != JsonValueKind.Object) return false;
            var name = expression.EnumerateObject().FirstOrDefault().Name;
            return name is "exthdr" or "tcp option" or "sctp chunk" or "dccp option";
        }

        private string RenderSet(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Array)
                return $"{{ {Expression(value)} }}";
            var items = value.EnumerateArray().ToArray();
            if (items.All(item => item.ValueKind == JsonValueKind.Array &&
                    item.GetArrayLength() == 2))
                return "{ " + string.Join(", ", items.Select(item =>
                    $"{Expression(item[0])} : {Expression(item[1])}")) + " }";
            return "{ " + string.Join(", ", items.Select(Expression)) + " }";
        }

        private string RenderSetItems(JsonElement value) =>
            "{ " + string.Join(", ", value.EnumerateArray().Select(Expression)) + " }";

        private string RenderRange(JsonElement value)
        {
            var items = Array(value);
            if (items.Length != 2)
                throw Unsupported("an nft range must have two endpoints", value);
            return $"{Expression(items[0])}-{Expression(items[1])}";
        }

        private static string RenderImmediate(string value)
        {
            if (value == "*") return value;
            if (value.StartsWith('@'))
                return "@" + RenderIdentifier(value[1..]);
            if (IPAddress.TryParse(value, out _) || IsMacAddress(value)) return value;
            if (IsBareToken(value)) return value;
            return NftSyntax.StringLiteral(value);
        }

        private static bool IsMacAddress(string value)
        {
            try
            {
                var bytes = PhysicalAddress.Parse(value.Replace(":", string.Empty, StringComparison.Ordinal)
                    .Replace("-", string.Empty, StringComparison.Ordinal)).GetAddressBytes();
                return bytes.Length == 6;
            }
            catch (FormatException) { return false; }
        }

        private static string RenderPayload(JsonElement value)
        {
            if (value.TryGetProperty("protocol", out var protocol))
                return $"{protocol.GetString()} {RequiredString(value, "field")}";
            return $"@{RequiredString(value, "base")},{RequiredInt64(value, "offset")}," +
                RequiredInt64(value, "len");
        }

        private static string RenderNamedField(
            string prefix,
            JsonElement value,
            bool includeOffset = false)
        {
            var name = RequiredString(value, "name");
            var result = string.IsNullOrEmpty(prefix) ? name : $"{prefix} {name}";
            if (value.TryGetProperty("field", out var field)) result += " " + field.GetString();
            if (includeOffset && value.TryGetProperty("offset", out var offset))
                result += " " + offset.GetRawText();
            return result;
        }

        private static string RenderRt(JsonElement value)
        {
            var result = "rt";
            if (value.TryGetProperty("family", out var family)) result += " " + family.GetString();
            return result + " " + RequiredString(value, "key");
        }

        private static string RenderCt(JsonElement value)
        {
            var result = "ct";
            if (value.TryGetProperty("dir", out var direction))
                result += " " + direction.GetString();
            if (value.TryGetProperty("family", out var family))
                result += " " + family.GetString();
            return result + " " + RequiredString(value, "key");
        }

        private static string RenderNumgen(JsonElement value)
        {
            var result = $"numgen {RequiredString(value, "mode")} mod " +
                RequiredInt64(value, "mod");
            if (TryInt64(value, "offset", out var offset) && offset != 0)
                result += " offset " + offset.ToString(CultureInfo.InvariantCulture);
            return result;
        }

        private string RenderJhash(JsonElement value)
        {
            var result = $"jhash {Expression(Required(value, "expr"))} mod " +
                RequiredInt64(value, "mod");
            if (TryInt64(value, "seed", out var seed) && seed != 0) result += " seed " + seed;
            if (TryInt64(value, "offset", out var offset) && offset != 0)
                result += " offset " + offset;
            return result;
        }

        private static string RenderSymhash(JsonElement value)
        {
            var result = "symhash mod " + RequiredInt64(value, "mod");
            if (TryInt64(value, "offset", out var offset) && offset != 0)
                result += " offset " + offset;
            return result;
        }

        private static string RenderFib(JsonElement value)
        {
            var flags = StringList(Required(value, "flags"));
            return "fib " + string.Join(" . ", flags) + " " + RequiredString(value, "result");
        }

        private string RenderBinary(string operation, JsonElement value)
        {
            var operands = Array(value);
            if (operands.Length < 2)
                throw Unsupported("an nft binary operation needs at least two operands", value);
            return "( " + string.Join($" {operation} ", operands.Select(Expression)) + " )";
        }

        private string RenderElement(JsonElement value)
        {
            var result = Expression(Required(value, "val"));
            if (TryInt64(value, "timeout", out var timeout)) result += $" timeout {timeout}ms";
            if (TryInt64(value, "expires", out var expires)) result += $" expires {expires}ms";
            if (value.TryGetProperty("comment", out var comment))
                result += " comment " + NftSyntax.StringLiteral(comment.GetString()!);
            return result;
        }

        private static string RenderOsf(JsonElement value)
        {
            var result = "osf";
            if (value.TryGetProperty("ttl", out var ttl)) result += " ttl " + ttl.GetString();
            return result + " " + RequiredString(value, "key");
        }

        private static string RenderJump(string kind, JsonElement value) =>
            $"{kind} {RenderIdentifier(RequiredString(value, "target"))}";

        private static string RenderCounter(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.String)
                return "counter name " + RenderIdentifier(value.GetString()!);
            if (value.ValueKind != JsonValueKind.Object)
                throw Unsupported("invalid nft counter statement", value);
            var result = "counter";
            if (TryInt64(value, "packets", out var packets)) result += " packets " + packets;
            if (TryInt64(value, "bytes", out var bytes)) result += " bytes " + bytes;
            return result;
        }

        private static string RenderQuota(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.String)
                return "quota name " + RenderIdentifier(value.GetString()!);
            var result = "quota";
            if (TryBoolean(value, "inv", out var inverse)) result += inverse ? " over" : " until";
            result += $" {RequiredInt64(value, "val")} {OptionalString(value, "val_unit") ?? "bytes"}";
            if (TryInt64(value, "used", out var used))
                result += $" used {used} {OptionalString(value, "used_unit") ?? "bytes"}";
            return result;
        }

        private static string RenderLimit(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.String)
                return "limit name " + RenderIdentifier(value.GetString()!);
            var result = "limit rate";
            if (TryBoolean(value, "inv", out var inverse) && inverse) result += " over";
            var rate = RequiredInt64(value, "rate");
            var rateUnit = OptionalString(value, "rate_unit") ?? "packets";
            var per = RequiredString(value, "per");
            result += rateUnit == "packets" ? $" {rate}/{per}" : $" {rate} {rateUnit}/{per}";
            if (TryInt64(value, "burst", out var burst) && burst != 0)
            {
                result += " burst " + burst;
                var burstUnit = OptionalString(value, "burst_unit");
                if (!string.IsNullOrWhiteSpace(burstUnit)) result += " " + burstUnit;
            }
            return result;
        }

        private string RenderFwd(JsonElement value)
        {
            var device = Expression(Required(value, "dev"));
            if (value.TryGetProperty("addr", out var address))
                return $"fwd {RequiredString(value, "family")} to {Expression(address)} " +
                    $"device {device}";
            return "fwd to " + device;
        }

        private string RenderDup(JsonElement value)
        {
            var result = "dup to " + Expression(Required(value, "addr"));
            if (value.TryGetProperty("dev", out var device))
                result += " device " + Expression(device);
            return result;
        }

        private string RenderNat(string kind, JsonElement value)
        {
            var result = kind;
            if (value.ValueKind == JsonValueKind.Null) return result;
            var hasAddress = value.TryGetProperty("addr", out var address);
            var hasPort = value.TryGetProperty("port", out var port);
            if (value.TryGetProperty("family", out var family)) result += " " + family.GetString();
            if (hasAddress || hasPort)
            {
                result += " to ";
                if (hasAddress) result += Expression(address);
                if (hasPort) result += ":" + Expression(port);
            }
            var flags = OptionalStringList(value, "flags");
            if (flags.Count > 0) result += " " + string.Join(',', flags);
            return result;
        }

        private string RenderReject(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Null ||
                value.ValueKind == JsonValueKind.Object && !value.EnumerateObject().Any())
                return "reject";
            var type = OptionalString(value, "type");
            if (string.IsNullOrWhiteSpace(type)) return "reject";
            var result = "reject with " + type;
            if (value.TryGetProperty("expr", out var expression))
                result += " type " + Expression(expression);
            return result;
        }

        private string RenderDynamicSet(JsonElement value)
        {
            var set = RequiredString(value, "set");
            if (set.StartsWith('@')) set = set[1..];
            return $"{RequiredString(value, "op")} @{RenderIdentifier(set)} " +
                $"{{ {Expression(Required(value, "elem"))} }}";
        }

        private static string RenderLog(JsonElement value)
        {
            var parts = new List<string> { "log" };
            if (value.TryGetProperty("prefix", out var prefix))
                parts.Add("prefix " + NftSyntax.StringLiteral(prefix.GetString()!));
            AddNumberOption(parts, value, "group");
            AddNumberOption(parts, value, "snaplen");
            AddNumberOption(parts, value, "queue-threshold");
            if (value.TryGetProperty("level", out var level)) parts.Add("level " + level.GetString());
            var flags = OptionalStringList(value, "flags");
            if (flags.Count > 0) parts.Add("flags " + string.Join(',', flags));
            return string.Join(' ', parts);
        }

        private string RenderMeter(JsonElement value) =>
            $"meter {RenderIdentifier(RequiredString(value, "name"))} " +
            $"{{ {Expression(Required(value, "key"))} {Statement(Required(value, "stmt"))} }}";

        private string RenderQueue(JsonElement value)
        {
            var result = "queue";
            if (value.TryGetProperty("num", out var number)) result += " num " + Expression(number);
            var flags = OptionalStringList(value, "flags");
            if (flags.Count > 0) result += " flags " + string.Join(',', flags);
            return result;
        }

        private static string RenderCtCount(JsonElement value)
        {
            var result = "ct count";
            if (TryBoolean(value, "inv", out var inverse) && inverse) result += " over";
            return result + " " + RequiredInt64(value, "val");
        }

        private static string RenderIdentifier(string value) =>
            IsBareIdentifier(value) ? value : NftSyntax.StringLiteral(value);

        private static bool IsBareIdentifier(string value) =>
            value.Length > 0 && char.IsAsciiLetter(value[0]) &&
            value.All(character => char.IsAsciiLetterOrDigit(character) ||
                character is '/' or '\\' or '_' or '.');

        private static bool IsBareToken(string value) =>
            value.Length > 0 && value.All(character => char.IsAsciiLetterOrDigit(character) ||
                character is '/' or '\\' or '_' or '.' or ':');

        private static (string Name, JsonElement Value) SingleProperty(
            JsonElement element,
            string kind)
        {
            if (element.ValueKind != JsonValueKind.Object)
                throw Unsupported($"an nft JSON {kind} must be an object", element);
            var properties = element.EnumerateObject().ToArray();
            if (properties.Length != 1)
                throw Unsupported($"an nft JSON {kind} must have exactly one property", element);
            return (properties[0].Name, properties[0].Value);
        }

        private static JsonElement Required(JsonElement obj, string property) =>
            obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(property, out var value)
                ? value
                : throw Unsupported($"missing nft JSON property '{property}'", obj);

        private static string RequiredString(JsonElement obj, string property)
        {
            var value = Required(obj, property);
            return value.ValueKind == JsonValueKind.String
                ? value.GetString()!
                : throw Unsupported($"nft JSON property '{property}' must be a string", value);
        }

        private static string? OptionalString(JsonElement obj, string property) =>
            obj.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;

        private static long RequiredInt64(JsonElement obj, string property)
        {
            var value = Required(obj, property);
            return value.TryGetInt64(out var result)
                ? result
                : throw Unsupported($"nft JSON property '{property}' must be an integer", value);
        }

        private static bool TryInt64(JsonElement obj, string property, out long result)
        {
            result = default;
            return obj.TryGetProperty(property, out var value) && value.TryGetInt64(out result);
        }

        private static bool TryBoolean(JsonElement obj, string property, out bool result)
        {
            if (obj.TryGetProperty(property, out var value) &&
                (value.ValueKind is JsonValueKind.True or JsonValueKind.False))
            {
                result = value.GetBoolean();
                return true;
            }
            result = default;
            return false;
        }

        private static JsonElement[] Array(JsonElement value) =>
            value.ValueKind == JsonValueKind.Array
                ? value.EnumerateArray().ToArray()
                : throw Unsupported("expected an nft JSON array", value);

        private static IReadOnlyList<string> StringList(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.String) return [value.GetString()!];
            if (value.ValueKind != JsonValueKind.Array)
                throw Unsupported("expected an nft JSON string or string array", value);
            return value.EnumerateArray().Select(item => item.ValueKind == JsonValueKind.String
                ? item.GetString()!
                : throw Unsupported("expected a string in an nft JSON array", item)).ToArray();
        }

        private static IReadOnlyList<string> OptionalStringList(
            JsonElement obj,
            string property) =>
            obj.TryGetProperty(property, out var value) ? StringList(value) : [];

        private static void AddNumberOption(
            ICollection<string> output,
            JsonElement obj,
            string property)
        {
            if (obj.TryGetProperty(property, out var value))
                output.Add(property + " " + value.GetRawText());
        }

        private static NftRuleRenderingException Unsupported(string message, JsonElement value) =>
            new($"{message}: {value.GetRawText()}");
    }
}