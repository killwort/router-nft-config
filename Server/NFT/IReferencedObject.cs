namespace RouterNftConfig.Server.NFT;

public interface IReferencedObject
{
    NftFamily Family { get; }
    string Table { get; }
    string Name { get; }
}

public static class ReferencedObjectExtensions
{
    public static bool Matches(this IReferencedObject self, IReferencedObject other) => self.Family == other.Family && self.Table == other.Table && self.Name == other.Name;
}