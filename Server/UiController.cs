using Microsoft.AspNetCore.Mvc;

namespace RouterNftConfig.Server;

public class UiController : Microsoft.AspNetCore.Mvc.Controller
{
    [HttpGet("{**path}")]
    public IActionResult Index() => new PhysicalFileResult(Path.Combine(Environment.CurrentDirectory, "dist", "index.html"), "text/html");

    [HttpGet("favicon.ico")]
    public IActionResult Favicon() => new PhysicalFileResult(Path.Combine(Environment.CurrentDirectory, "dist", "favicon.ico"), "application/octet-stream");

    [HttpGet("assets/{*path}")]
    public IActionResult Asset([FromRoute] string path) => Content(System.IO.File.ReadAllText(Path.Combine(Environment.CurrentDirectory, "dist", "assets", path)),
        Path.GetExtension(path) switch
        {
            ".css" => "text/css",
            ".js" => "application/javascript",
            _ => "application/octet-stream"
        }
    );
}