namespace RouterNftConfig.Server.Models;

public class UpdateHostRequest
{
    public string MacAddress { get; set; }
    public string Name { get; set; }
    public string[] Groups { get; set; }
}