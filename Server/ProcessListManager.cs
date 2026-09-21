using System.Net.NetworkInformation;
using System.Text.Json;
using RouterNftConfig.Server.Models;

namespace RouterNftConfig.Server;

public class ProcessListManager
{
    private readonly string _storeRoot;

    public ProcessListManager()
    {
        _storeRoot = Path.Combine(Environment.CurrentDirectory, "process-lists");
        if (!Directory.Exists(_storeRoot)) Directory.CreateDirectory(_storeRoot);
        Console.WriteLine($"Using {_storeRoot} to store process lists");
    }

    public async Task RegisterSnapshot(PhysicalAddress address, ProcessInfo[] snapshot)
    {
        var file = Path.Combine(_storeRoot, $"{address}.json");
        HourBucket?[]? data = null;
        if (File.Exists(file))
            try
            {
                data = JsonSerializer.Deserialize<HourBucket?[]>(await File.ReadAllTextAsync(file));
            }
            catch
            {
                data = null;
            }

        if (data == null || data.Length != 168)
            data = new HourBucket?[168];
        var hour = DateTime.Now;
        hour = new DateTime(hour.Year, hour.Month, hour.Day, hour.Hour, 0, 0);
        int index = (int)(hour.Ticks / TimeSpan.TicksPerHour % 168);
        var bucket = data[index];
        if (bucket == null)
            data[index] = bucket = new HourBucket();

        if (bucket.Hour != hour)
        {
            bucket.Hour = hour;
            bucket.Processes.Clear();
        }

        bucket.Processes.UnionWith(snapshot.Select(x=>x.FullPath));
        await File.WriteAllTextAsync(file, JsonSerializer.Serialize(data));
    }

    public bool HasData(PhysicalAddress address)
    {
        return File.Exists(Path.Combine(_storeRoot, $"{address}.json"));
    }

    public async Task<HourBucket?[]?> GetReport(PhysicalAddress address)
    {
        var file = Path.Combine(_storeRoot, $"{address}.json");
        HourBucket?[]? data = null;
        if (File.Exists(file))
            try
            {
                data = JsonSerializer.Deserialize<HourBucket?[]>(await File.ReadAllTextAsync(file));
            }
            catch
            {
                data = null;
            }

        if (data == null || data.Length != 168)
            data = new HourBucket?[168];
        return data;
    }
}