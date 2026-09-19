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
        ActionType = src.ActionType;
        ActionValue = src.ActionValue;
    }

    public TriggerType TriggerType { get; set; }
    public string TriggerValue { get; set; }
    public FirewallActionType ActionType{ get; set; }
    public string ActionValue { get; set; }
}