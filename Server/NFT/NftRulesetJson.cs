using System.Text.Json;
using System;
using System.Collections.Generic;
using System.Linq;

namespace RouterNftConfig.Server.NFT;

public static class NftRulesetJson
{
    public static NftRuleset Parse(string json)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(json);
        using var document = JsonDocument.Parse(json);
        if (!document.RootElement.TryGetProperty("nftables", out var nftables) ||
            nftables.ValueKind != JsonValueKind.Array)
            throw new JsonException("Expected a root object containing an 'nftables' array.");

        NftMetainfo? metainfo = null;
        var tables = new List<NftTable>();
        var chains = new List<NftChain>();
        var sets = new List<NftSet>();
        var rules = new List<NftRule>();
        var unknown = new List<NftUnknownObject>();

        foreach (var item in nftables.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                unknown.Add(new NftUnknownObject("<non-object>", item.Clone()));
                continue;
            }

            if (item.TryGetProperty("metainfo", out var meta))
            {
                metainfo = new NftMetainfo(
                    String(meta, "version"),
                    String(meta, "release_name"),
                    Int32(meta, "json_schema_version"));
            }
            else if (item.TryGetProperty("table", out var table))
            {
                tables.Add(new NftTable(
                    Family(table), RequiredString(table, "name"), Int64(table, "handle"),
                    Strings(table, "flags"), table.Clone()));
            }
            else if (item.TryGetProperty("chain", out var chain))
            {
                chains.Add(new NftChain(
                    Family(chain), RequiredString(chain, "table"), RequiredString(chain, "name"),
                    Int64(chain, "handle"), String(chain, "type"), String(chain, "hook"),
                    Int32(chain, "prio"), String(chain, "dev"), String(chain, "policy"),
                    String(chain, "comment"), chain.Clone()));
            }
            else if (item.TryGetProperty("set", out var set))
            {
                sets.Add(new NftSet(
                    Family(set), RequiredString(set, "table"), RequiredString(set, "name"),
                    Int64(set, "handle"), SetTypes(set), Strings(set, "flags"),
                    Elements(set), Int64(set, "timeout"), Int64(set, "gc-interval"),
                    Int32(set, "size"), String(set, "comment"), set.Clone()));
            }
            else if (item.TryGetProperty("rule", out var rule))
            {
                rules.Add(new NftRule(
                    Family(rule), RequiredString(rule, "table"), RequiredString(rule, "chain"),
                    Int64(rule, "handle"), Int64(rule, "index"), String(rule, "comment"),
                    Array(rule, "expr"), rule.Clone()));
            }
            else
            {
                var kind = item.EnumerateObject().FirstOrDefault().Name ?? "<empty>";
                unknown.Add(new NftUnknownObject(kind, item.Clone()));
            }
        }

        return new NftRuleset(metainfo, tables, chains, sets, rules, unknown);
    }

    private static NftFamily Family(JsonElement obj) =>
        NftFamilyExtensions.ParseNftFamily(RequiredString(obj, "family"));

    private static string RequiredString(JsonElement obj, string property) =>
        String(obj, property) ?? throw new JsonException($"Missing string property '{property}'.");

    private static string? String(JsonElement obj, string property) =>
        obj.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static long? Int64(JsonElement obj, string property) =>
        obj.TryGetProperty(property, out var value) && value.TryGetInt64(out var result) ? result : null;

    private static int? Int32(JsonElement obj, string property) =>
        obj.TryGetProperty(property, out var value) && value.TryGetInt32(out var result) ? result : null;

    private static IReadOnlyList<string> Strings(JsonElement obj, string property)
    {
        if (!obj.TryGetProperty(property, out var value)) return [];
        if (value.ValueKind == JsonValueKind.String) return [value.GetString()!];
        if (value.ValueKind != JsonValueKind.Array) return [];
        return value.EnumerateArray()
            .Where(x => x.ValueKind == JsonValueKind.String)
            .Select(x => x.GetString()!)
            .ToArray();
    }

    private static IReadOnlyList<string> SetTypes(JsonElement set)
    {
        if (!set.TryGetProperty("type", out var type)) return [];
        if (type.ValueKind == JsonValueKind.String) return [type.GetString()!];
        if (type.ValueKind == JsonValueKind.Array)
            return type.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => x.GetString()!).ToArray();
        return [];
    }

    private static IReadOnlyList<JsonElement> Elements(JsonElement set)
    {
        if (!set.TryGetProperty("elem", out var elem)) return [];
        return elem.ValueKind == JsonValueKind.Array
            ? elem.EnumerateArray().Select(x => x.Clone()).ToArray()
            : [elem.Clone()];
    }

    private static IReadOnlyList<JsonElement> Array(JsonElement obj, string property) =>
        obj.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Select(x => x.Clone()).ToArray()
            : [];
}
