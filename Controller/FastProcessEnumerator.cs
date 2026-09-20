using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Controller;

public static unsafe class FastProcessEnumerator
{
    public readonly record struct ProcessInfo(
        int Pid,
        string FullPath,
        DateTime StartTime);

    private const int SystemProcessInformation = 5;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;

    private const int TokenUser = 1;

    // WELL_KNOWN_SID_TYPE
    private const int WinLocalSystemSid = 22;
    private const int WinLocalServiceSid = 23;
    private const int WinNetworkServiceSid = 24;

    public static List<ProcessInfo> GetProcesses()
    {
        nint buffer = 0;
        int bufferSize = 1024 * 1024;

        try
        {
            // Обычно первого мегабайта хватает.
            // Если нет — увеличиваем буфер.
            while (true)
            {
                buffer = Marshal.AllocHGlobal(bufferSize);

                int status = NtQuerySystemInformation(
                    SystemProcessInformation,
                    buffer,
                    bufferSize,
                    out int requiredSize);

                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = 0;

                    bufferSize = Math.Max(
                        bufferSize * 2,
                        requiredSize + 64 * 1024);

                    continue;
                }

                if (status < 0)
                    throw new Win32Exception(
                        $"NtQuerySystemInformation failed: 0x{status:X8}");

                break;
            }

            var result = new List<ProcessInfo>(256);

            byte* entry = (byte*)buffer;

            while (true)
            {
                var spi = (SYSTEM_PROCESS_INFORMATION*)entry;

                long pid64 = spi->UniqueProcessId;

                if (pid64 > 0 && pid64 <= uint.MaxValue)
                {
                    uint pid = (uint)pid64;

                    TryAddProcess(
                        result,
                        pid,
                        spi->CreateTime);
                }

                if (spi->NextEntryOffset == 0)
                    break;

                entry += spi->NextEntryOffset;
            }

            return result;
        }
        finally
        {
            if (buffer != 0)
                Marshal.FreeHGlobal(buffer);
        }
    }

    private static void TryAddProcess(
        List<ProcessInfo> result,
        uint pid,
        long createTime)
    {
        nint processHandle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid);

        if (processHandle == 0)
            return;

        try
        {
            //
            // Сначала проверяем пользователя.
            // Если это системный account, path уже получать незачем.
            //

            if (!OpenProcessToken(
                    processHandle,
                    TOKEN_QUERY,
                    out nint tokenHandle))
            {
                return;
            }

            try
            {
                byte* tokenBuffer = stackalloc byte[128];

                if (!GetTokenInformation(
                        tokenHandle,
                        TokenUser,
                        tokenBuffer,
                        128,
                        out _))
                {
                    return;
                }

                var tokenUser = (TOKEN_USER*)tokenBuffer;
                nint sid = tokenUser->User.Sid;

                if (IsWellKnownSid(sid, WinLocalSystemSid) ||
                    IsWellKnownSid(sid, WinLocalServiceSid) ||
                    IsWellKnownSid(sid, WinNetworkServiceSid))
                {
                    return;
                }
            }
            finally
            {
                CloseHandle(tokenHandle);
            }

            //
            // Это не один из системных SID.
            // Получаем полный путь.
            //

            Span<char> pathBuffer = stackalloc char[1024];

            fixed (char* path = pathBuffer)
            {
                uint length = (uint)pathBuffer.Length;

                if (!QueryFullProcessImageName(
                        processHandle,
                        0,
                        path,
                        ref length))
                {
                    return;
                }

                string fullPath = new(path, 0, checked((int)length));

                DateTime startTime =
                    DateTime.FromFileTimeUtc(createTime)
                        .ToLocalTime();

                result.Add(new ProcessInfo(
                    checked((int)pid),
                    fullPath,
                    startTime));
            }
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    #region Native structures

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public nint Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;

        public long WorkingSetPrivateSize;
        public uint HardFaultCount;
        public uint NumberOfThreadsHighWatermark;
        public ulong CycleTime;

        public long CreateTime;
        public long UserTime;
        public long KernelTime;

        public UNICODE_STRING ImageName;

        public int BasePriority;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;

        public uint HandleCount;
        public uint SessionId;
        public nuint UniqueProcessKey;

        public nuint PeakVirtualSize;
        public nuint VirtualSize;

        public uint PageFaultCount;

        public nuint PeakWorkingSetSize;
        public nuint WorkingSetSize;

        public nuint QuotaPeakPagedPoolUsage;
        public nuint QuotaPagedPoolUsage;
        public nuint QuotaPeakNonPagedPoolUsage;
        public nuint QuotaNonPagedPoolUsage;

        public nuint PagefileUsage;
        public nuint PeakPagefileUsage;
        public nuint PrivatePageCount;

        public long ReadOperationCount;
        public long WriteOperationCount;
        public long OtherOperationCount;
        public long ReadTransferCount;
        public long WriteTransferCount;
        public long OtherTransferCount;
    }

    #endregion

    #region Native methods

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass,
        nint systemInformation,
        int systemInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        nint processHandle,
        uint desiredAccess,
        out nint tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        nint tokenHandle,
        int tokenInformationClass,
        void* tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWellKnownSid(
        nint sid,
        int wellKnownSidType);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(
        nint processHandle,
        uint flags,
        char* exeName,
        ref uint size);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint handle);

    #endregion
}