namespace RouterNftConfig.Server.Models;

public class Host
{
    public string Name { get; set; }
    public string? Hostname { get; set; }
    public string[] IpAddress { get; set; }
    public string? MacAddress { get; set; }
    public string? MacAddressInfo { get; set; }
    public string[] Groups { get; set; }
    public bool IsOnline { get; set; }
    public bool HasProcessReport { get; set; }
    public bool IsKnown { get; set; }
    public bool IsHidden { get; set; }
}