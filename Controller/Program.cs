using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Controller;

class Program
{
    static HttpClient HttpClient = new();
    private static string BaseUrl = "http://10.132.35.254/";
    private static string WatchedFlag = "VasyaHomeworkCompleted";
    static async Task Main(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--flag":
                    WatchedFlag = args[++i];
                    break;
                case "--server":
                    BaseUrl = args[++i];
                    break;
                default:
                    Console.WriteLine($"Unknown argument {args[i]}");
                    return;
            }
        }
        
        while (true)
        {
            bool isAllowedToRunAllProcesses;
            try
            {
                isAllowedToRunAllProcesses = string.Equals(await HttpClient.GetStringAsync($"{BaseUrl}api/flag/{WatchedFlag}"), "true", StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception e)
            {
                Console.WriteLine($"Cannot retrieve flag value: {e}");
                isAllowedToRunAllProcesses = true;
            }

            string[] forbiddenProcesses=[];
            if (!isAllowedToRunAllProcesses)
            {
                try
                {
                    forbiddenProcesses = JsonSerializer.Deserialize<string[]>(await HttpClient.GetStringAsync($"{BaseUrl}api/process/forbidden"));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Cannot retrieve forbidden process names: {e}");
                }
            }

            var processes = FastProcessEnumerator.GetProcesses();
            if (!isAllowedToRunAllProcesses)
            {
                foreach (var process in processes)
                {
                    if (forbiddenProcesses.Contains(Path.GetFileName(process.FullPath), StringComparer.OrdinalIgnoreCase) ||
                        forbiddenProcesses.Contains(process.FullPath, StringComparer.OrdinalIgnoreCase))
                    {
                        try
                        {
                            Process.GetProcessById(process.Pid).Kill();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Cannot kill process {process.Pid} {process.FullPath}: {e}");
                        }
                    }
                }
            }

            try
            {
                await HttpClient.PostAsync($"{BaseUrl}api/process/upload-report", JsonContent.Create(processes));
            }
            catch (Exception e)
            {
                Console.WriteLine($"Cannot upload running processes report: {e}");
            }

            await Task.Delay(TimeSpan.FromMinutes(1));
        }
    }
}