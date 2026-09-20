namespace RouterNftConfig.Server.Models;

public class DefinitionsResponse
{
    public string[] Groups { get; set; }
    public Dictionary<string,bool> Flags { get; set; }
}