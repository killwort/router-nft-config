namespace RouterNftConfig.Server.Models;

public class FirewallAction : FirewallActionDefinition
{
    public FirewallAction()
    {
    }

    public FirewallAction(FirewallActionDefinition src) : base(src)
    {
    }

    public string Id { get; set; }

    public override string ToString()
    {
        return $"{Id} {TriggerType} {TriggerValue} for {ActionType} {ActionValue}";
    }
}