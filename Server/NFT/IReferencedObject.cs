namespace RouterNftConfig.Server.NFT;

public interface IReferencedObject
{
    NftFamily Family { get; }
    string Table { get; }
    string Name { get; }
}