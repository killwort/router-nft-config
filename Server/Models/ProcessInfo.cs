namespace RouterNftConfig.Server.Models;

public readonly record struct ProcessInfo(
    int Pid,
    string FullPath,
    DateTime StartTime);