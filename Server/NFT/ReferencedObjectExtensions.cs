namespace RouterNftConfig.Server.NFT;

public static class ReferencedObjectExtensions
{
    public static bool Matches(this IReferencedObject self, IReferencedObject other) =>
        self.Family == other.Family && self.Table == other.Table && self.Name == other.Name;
}