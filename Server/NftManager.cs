using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using RouterNftConfig.Server.Models;

namespace RouterNftConfig.Server;

public class NftManager
{
    private readonly string _configFile;
    public NftManager(IConfiguration config)
    {
        _configFile = config["configFile"] ?? "config.json";

    }
    public async Task<Configuration> GetConfiguration()
    {
        if (!System.IO.File.Exists(_configFile)) return new Configuration();
        return System.Text.Json.JsonSerializer.Deserialize<Configuration>(await System.IO.File.ReadAllTextAsync(_configFile), Options) ??
               new Configuration();
    }

    private static readonly JsonSerializerOptions Options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = true
    };

    public async Task SaveConfiguration(Configuration config)
    {
        await System.IO.File.WriteAllTextAsync(_configFile, System.Text.Json.JsonSerializer.Serialize(config, Options));
    }

    public async Task SetFlag(string name, bool isSet)
    {
        
    }
}