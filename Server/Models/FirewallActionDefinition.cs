namespace RouterNftConfig.Server.Models;

public class FirewallActionDefinition
{
    protected FirewallActionDefinition()
    {
    }
    protected FirewallActionDefinition(FirewallActionDefinition src)
    {
        TriggerType = src.TriggerType;
        TriggerValue = src.TriggerValue;
        Action = src.Action;
        Group = src.Group;
        Flag = src.Flag;
    }

    public TriggerType TriggerType { get; set; }
    public string TriggerValue { get; set; }
    public FirewallActionType Action { get; set; }
    public string? Group { get; set; }
    public string? Flag { get; set; }
}