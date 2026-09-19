using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Html;

namespace RouterNftConfig.Server;

public class ManifestLoader
{
    private readonly FileSystemWatcher _manifestWatcher;
    private ConcurrentDictionary<string, string[]> _manifest;
    private static readonly object Sync = new object();
    private readonly string _distPath;

    public ManifestLoader() {
        _distPath = Path.Combine(Environment.CurrentDirectory, "dist");
        _manifestWatcher = new FileSystemWatcher(_distPath, "manifest.json");
        _manifestWatcher.Changed += (_, __) => _manifest = null;
        _manifestWatcher.Created += (_, __) => _manifest = null;
        _manifestWatcher.Deleted += (_, __) => _manifest = null;
        _manifestWatcher.EnableRaisingEvents = true;
    }

    private ConcurrentDictionary<string, string[]> Manifest
    {
        get
        {
            if (_manifest != null) return _manifest;
            lock (Sync)
            {
                _manifest = new ConcurrentDictionary<string, string[]>();
                var mInfo = Path.Combine(_distPath, "manifest.json");
                if (File.Exists(mInfo))
                {
                    var data = JsonNode.Parse(File.ReadAllText(mInfo)) as JsonObject;
                    foreach (var prop in data)
                    {
                        _manifest.TryAdd(prop.Key, ((JsonArray)prop.Value).Select(x => x.GetValue<string>()).ToArray());
                    }
                }
            }

            return _manifest;
        }
    }

    public IHtmlContent Load(string entryPoint, string fileType=null)
    {
        var tags = "";
        if (Manifest.TryGetValue(entryPoint, out var eps))
        {
            foreach (var ep in eps)
            {
                if (fileType != null && !ep.EndsWith(fileType)) continue;
                if (ep.EndsWith(".js"))
                    tags += $"<script src=\"{ep}\" type=\"text/javascript\" async></script>";
                else if (ep.EndsWith(".css"))
                    tags += $"<link rel=\"stylesheet\" href=\"{ep}\">";
            }
        }

        return new HtmlString(tags);
    }
    public string RootPath(string entryPoint)
    {
        var tags = "";
        if (Manifest.TryGetValue(entryPoint, out var eps)) {
            var l = eps.First().LastIndexOf('/');
            return eps.First().Substring(0, l + 1);
        }

        return "/dist/";
    }
        
}