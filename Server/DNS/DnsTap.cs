using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RouterNftConfig.Server.DNS;

/// <summary>
/// Receives dnstap Frame Streams on a Unix domain socket and reports A/AAAA
/// records found in DNS response messages.
/// </summary>
public sealed class DnstapListener
{
    private const string DnstapContentType = "protobuf:dnstap.Dnstap";
    private const int MaximumDataFrameLength = 16 * 1024 * 1024;
    private const int MaximumControlFrameLength = 64 * 1024;

    private readonly string _socketPath;
    private readonly UnixFileMode _socketMode;
    private Socket? _listener;
    private int _started;

    /// <param name="socketPath">Path at which the Unix domain socket is created.</param>
    /// <param name="socketMode">
    /// Permissions applied after binding. The Unbound user must be able to connect to the socket.
    /// </param>
    public DnstapListener(
        string socketPath = "/run/dnstap.sock",
        UnixFileMode socketMode = UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                  UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                                  UnixFileMode.OtherRead | UnixFileMode.OtherWrite)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(socketPath);
        _socketPath = Path.GetFullPath(socketPath);
        _socketMode = socketMode;
    }

    /// <summary>
    /// Creates the Unix domain socket and starts a background receiver. The method returns after
    /// the socket has been bound and is ready for Unbound to connect. The callback is invoked
    /// serially on the receiver thread for every A or AAAA answer.
    /// </summary>
    public void Startup(Action<string, IPAddress, int> onResolution)
    {
        ArgumentNullException.ThrowIfNull(onResolution);
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
            throw new InvalidOperationException("The dnstap listener has already been started.");

        Socket? listener = null;
        try
        {
            var directory = Path.GetDirectoryName(_socketPath);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            // Unix socket nodes survive an unclean process exit.
            if (File.Exists(_socketPath)) File.Delete(_socketPath);

            listener = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            listener.Bind(new UnixDomainSocketEndPoint(_socketPath));
            listener.Listen(backlog: 4);
            File.SetUnixFileMode(_socketPath, _socketMode);
            _listener = listener;

            AppDomain.CurrentDomain.ProcessExit += HandleProcessExit;
            var thread = new Thread(() => AcceptLoop(listener, onResolution))
            {
                IsBackground = true,
                Name = "dnstap-listener"
            };
            thread.Start();
        }
        catch
        {
            listener?.Dispose();
            _listener = null;
            Interlocked.Exchange(ref _started, 0);
            TryDeleteSocketFile();
            throw;
        }
    }

    private void AcceptLoop(Socket listener, Action<string, IPAddress, int> onResolution)
    {
        while (true)
        {
            try
            {
                using var connection = listener.Accept();
                using var stream = new NetworkStream(connection, ownsSocket: false);
                ProcessConnection(stream, onResolution);
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException exception)
            {
                if (!ReferenceEquals(_listener, listener)) return;
                Trace.TraceError("dnstap socket error: {0}", exception);
            }
            catch (Exception exception)
            {
                Trace.TraceError("dnstap connection error: {0}", exception);
            }
        }
    }

    private static void ProcessConnection(
        Stream stream,
        Action<string, IPAddress, int> onResolution)
    {
        var first = ReadFrame(stream);
        if (first is null) return;
        if (!first.IsControl)
            throw new InvalidDataException("A Frame Streams connection must begin with a control frame.");

        var firstControl = ControlFrame.Parse(first.Payload);
        var bidirectional = firstControl.Type == ControlType.Ready;
        if (bidirectional)
        {
            firstControl.RequireContentType(DnstapContentType);
            WriteControlFrame(stream, ControlType.Accept, DnstapContentType);

            var start = ReadFrame(stream);
            if (start is null || !start.IsControl)
                throw new InvalidDataException("Expected a Frame Streams START control frame.");
            var startControl = ControlFrame.Parse(start.Payload);
            if (startControl.Type != ControlType.Start)
                throw new InvalidDataException("Expected a Frame Streams START control frame.");
            startControl.RequireContentType(DnstapContentType);
        }
        else
        {
            if (firstControl.Type != ControlType.Start)
                throw new InvalidDataException("Expected a Frame Streams READY or START control frame.");
            firstControl.RequireContentType(DnstapContentType);
        }

        while (ReadFrame(stream) is { } frame)
        {
            if (!frame.IsControl)
            {
                ProcessDnstapMessage(frame.Payload, onResolution);
                continue;
            }

            var control = ControlFrame.Parse(frame.Payload);
            if (control.Type != ControlType.Stop) continue;
            if (bidirectional) WriteControlFrame(stream, ControlType.Finish, contentType: null);
            return;
        }
    }

    private static void ProcessDnstapMessage(
        byte[] payload,
        Action<string, IPAddress, int> onResolution)
    {
        try
        {
            if (!DnstapParser.TryReadResponseMessage(payload, out var dnsMessage)) return;
            foreach (var resolution in DnsResponseParser.Parse(dnsMessage))
            {
                try
                {
                    onResolution(resolution.Name, resolution.Address, resolution.Ttl);
                }
                catch (Exception exception)
                {
                    Trace.TraceError("dnstap resolution callback error: {0}", exception);
                }
            }
        }
        catch (InvalidDataException exception)
        {
            // A bad event must not tear down the Frame Streams connection.
            Trace.TraceError("Invalid dnstap event: {0}", exception.Message);
        }
    }

    private static Frame? ReadFrame(Stream stream)
    {
        Span<byte> header = stackalloc byte[4];
        if (!TryReadExactly(stream, header)) return null;
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length != 0)
            return new Frame(false, ReadPayload(stream, length, MaximumDataFrameLength));

        ReadExactly(stream, header);
        var controlLength = BinaryPrimitives.ReadUInt32BigEndian(header);
        return new Frame(true, ReadPayload(stream, controlLength, MaximumControlFrameLength));
    }

    private static byte[] ReadPayload(Stream stream, uint length, int maximumLength)
    {
        if (length > (uint)maximumLength)
            throw new InvalidDataException($"Frame length {length} exceeds {maximumLength} bytes.");
        var payload = new byte[checked((int)length)];
        ReadExactly(stream, payload);
        return payload;
    }

    private static bool TryReadExactly(Stream stream, Span<byte> buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var count = stream.Read(buffer[offset..]);
            if (count == 0)
            {
                if (offset == 0) return false;
                throw new EndOfStreamException("Unexpected end of a Frame Streams frame.");
            }
            offset += count;
        }
        return true;
    }

    private static void ReadExactly(Stream stream, Span<byte> buffer)
    {
        if (!TryReadExactly(stream, buffer))
            throw new EndOfStreamException("Unexpected end of a Frame Streams frame.");
    }

    private static void WriteControlFrame(
        Stream stream,
        ControlType type,
        string? contentType)
    {
        var contentBytes = contentType is null ? null : Encoding.UTF8.GetBytes(contentType);
        var payloadLength = 4 + (contentBytes is null ? 0 : 8 + contentBytes.Length);
        var frame = new byte[8 + payloadLength];
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(4, 4), (uint)payloadLength);
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(8, 4), (uint)type);
        if (contentBytes is not null)
        {
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(12, 4), 1);
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(16, 4), (uint)contentBytes.Length);
            contentBytes.CopyTo(frame.AsSpan(20));
        }
        stream.Write(frame);
        stream.Flush();
    }

    private void HandleProcessExit(object? sender, EventArgs eventArgs)
    {
        var listener = Interlocked.Exchange(ref _listener, null);
        listener?.Dispose();
        TryDeleteSocketFile();
    }

    private void TryDeleteSocketFile()
    {
        try
        {
            if (File.Exists(_socketPath)) File.Delete(_socketPath);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private sealed record Frame(bool IsControl, byte[] Payload);

    private enum ControlType : uint
    {
        Accept = 1,
        Start = 2,
        Stop = 3,
        Ready = 4,
        Finish = 5
    }

    private sealed record ControlFrame(ControlType Type, IReadOnlyList<string> ContentTypes)
    {
        public static ControlFrame Parse(ReadOnlySpan<byte> payload)
        {
            if (payload.Length < 4)
                throw new InvalidDataException("A Frame Streams control frame is too short.");

            var type = (ControlType)BinaryPrimitives.ReadUInt32BigEndian(payload);
            var contentTypes = new List<string>();
            var offset = 4;
            while (offset < payload.Length)
            {
                if (payload.Length - offset < 8)
                    throw new InvalidDataException("A Frame Streams control field is truncated.");
                var fieldType = BinaryPrimitives.ReadUInt32BigEndian(payload[offset..]);
                var length = BinaryPrimitives.ReadUInt32BigEndian(payload[(offset + 4)..]);
                offset += 8;
                if (length > (uint)(payload.Length - offset))
                    throw new InvalidDataException("A Frame Streams control field is truncated.");
                if (fieldType == 1)
                    contentTypes.Add(Encoding.UTF8.GetString(payload.Slice(offset, (int)length)));
                offset += (int)length;
            }
            return new ControlFrame(type, contentTypes);
        }

        public void RequireContentType(string expected)
        {
            foreach (var value in ContentTypes)
                if (string.Equals(value, expected, StringComparison.Ordinal)) return;
            throw new InvalidDataException(
                $"Frame Streams peer did not offer the '{expected}' content type.");
        }
    }

    private static class DnstapParser
    {
        public static bool TryReadResponseMessage(
            ReadOnlySpan<byte> payload,
            out byte[] dnsMessage)
        {
            var outer = new ProtobufReader(payload);
            byte[]? message = null;
            ulong? dnstapType = null;
            while (outer.TryReadTag(out var field, out var wireType))
            {
                if (field == 14 && wireType == 2)
                    message = outer.ReadBytes().ToArray();
                else if (field == 15 && wireType == 0)
                    dnstapType = outer.ReadVarint();
                else
                    outer.Skip(wireType);
            }

            if (dnstapType != 1 || message is null)
            {
                dnsMessage = Array.Empty<byte>();
                return false;
            }

            var inner = new ProtobufReader(message);
            ulong? messageType = null;
            byte[]? response = null;
            while (inner.TryReadTag(out var field, out var wireType))
            {
                if (field == 1 && wireType == 0)
                    messageType = inner.ReadVarint();
                else if (field == 14 && wireType == 2)
                    response = inner.ReadBytes().ToArray();
                else
                    inner.Skip(wireType);
            }

            if (!messageType.HasValue || response is null)
            {
                dnsMessage = Array.Empty<byte>();
                return false;
            }

            var type = messageType.Value;
            if (type is < 2 or > 14 || (type & 1) != 0)
            {
                dnsMessage = Array.Empty<byte>();
                return false;
            }

            dnsMessage = response;
            return true;
        }
    }

    private ref struct ProtobufReader
    {
        private readonly ReadOnlySpan<byte> _data;
        private int _offset;

        public ProtobufReader(ReadOnlySpan<byte> data)
        {
            _data = data;
            _offset = 0;
        }

        public bool TryReadTag(out int field, out int wireType)
        {
            if (_offset == _data.Length)
            {
                field = 0;
                wireType = 0;
                return false;
            }

            var tag = ReadVarint();
            field = checked((int)(tag >> 3));
            wireType = (int)(tag & 7);
            if (field == 0) throw new InvalidDataException("Invalid protobuf field number 0.");
            return true;
        }

        public ulong ReadVarint()
        {
            ulong result = 0;
            for (var shift = 0; shift < 64; shift += 7)
            {
                if (_offset >= _data.Length)
                    throw new InvalidDataException("Truncated protobuf varint.");
                var value = _data[_offset++];
                result |= (ulong)(value & 0x7f) << shift;
                if ((value & 0x80) == 0) return result;
            }
            throw new InvalidDataException("Protobuf varint is too long.");
        }

        public ReadOnlySpan<byte> ReadBytes()
        {
            var length = ReadVarint();
            if (length > int.MaxValue || length > (ulong)(_data.Length - _offset))
                throw new InvalidDataException("Truncated protobuf length-delimited field.");
            var result = _data.Slice(_offset, (int)length);
            _offset += (int)length;
            return result;
        }

        public void Skip(int wireType)
        {
            switch (wireType)
            {
                case 0:
                    _ = ReadVarint();
                    break;
                case 1:
                    Advance(8);
                    break;
                case 2:
                    _ = ReadBytes();
                    break;
                case 5:
                    Advance(4);
                    break;
                default:
                    throw new InvalidDataException($"Unsupported protobuf wire type {wireType}.");
            }
        }

        private void Advance(int count)
        {
            if (count > _data.Length - _offset)
                throw new InvalidDataException("Truncated protobuf field.");
            _offset += count;
        }
    }

    private static class DnsResponseParser
    {
        public static IReadOnlyList<Resolution> Parse(ReadOnlySpan<byte> message)
        {
            var result = new List<Resolution>();
            if (message.Length < 12) return result;

            var flags = BinaryPrimitives.ReadUInt16BigEndian(message[2..]);
            if ((flags & 0x8000) == 0) return result;
            var questionCount = BinaryPrimitives.ReadUInt16BigEndian(message[4..]);
            var answerCount = BinaryPrimitives.ReadUInt16BigEndian(message[6..]);
            if (questionCount == 0) return result;

            var offset = 12;
            var queryName = ReadName(message, ref offset);
            Skip(message, ref offset, 4);
            for (var question = 1; question < questionCount; question++)
            {
                _ = ReadName(message, ref offset);
                Skip(message, ref offset, 4);
            }

            for (var answer = 0; answer < answerCount; answer++)
            {
                _ = ReadName(message, ref offset);
                EnsureAvailable(message, offset, 10);
                var type = BinaryPrimitives.ReadUInt16BigEndian(message[offset..]);
                var recordClass = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 2)..]);
                var rawTtl = BinaryPrimitives.ReadUInt32BigEndian(message[(offset + 4)..]);
                var ttl = rawTtl > int.MaxValue ? int.MaxValue : (int)rawTtl;
                var dataLength = BinaryPrimitives.ReadUInt16BigEndian(message[(offset + 8)..]);
                offset += 10;
                EnsureAvailable(message, offset, dataLength);

                if (recordClass == 1 && type == 1 && dataLength == 4)
                    result.Add(new Resolution(
                        queryName,
                        new IPAddress(message.Slice(offset, 4)),
                        ttl));
                else if (recordClass == 1 && type == 28 && dataLength == 16)
                    result.Add(new Resolution(
                        queryName,
                        new IPAddress(message.Slice(offset, 16)),
                        ttl));
                offset += dataLength;
            }

            return result;
        }

        private static string ReadName(ReadOnlySpan<byte> message, ref int offset)
        {
            var labels = new List<string>();
            var position = offset;
            var resumeAt = -1;
            var jumps = 0;

            while (true)
            {
                EnsureAvailable(message, position, 1);
                var length = message[position++];
                if ((length & 0xc0) == 0xc0)
                {
                    EnsureAvailable(message, position, 1);
                    var pointer = ((length & 0x3f) << 8) | message[position++];
                    if (pointer >= message.Length)
                        throw new InvalidDataException("DNS compression pointer is out of range.");
                    if (resumeAt < 0) resumeAt = position;
                    position = pointer;
                    if (++jumps > 128)
                        throw new InvalidDataException("DNS compression pointer loop detected.");
                    continue;
                }
                if ((length & 0xc0) != 0)
                    throw new InvalidDataException("Invalid DNS label length.");
                if (length == 0)
                {
                    offset = resumeAt >= 0 ? resumeAt : position;
                    return labels.Count == 0 ? "." : string.Join(".", labels);
                }

                EnsureAvailable(message, position, length);
                labels.Add(Encoding.ASCII.GetString(message.Slice(position, length)));
                position += length;
            }
        }

        private static void Skip(ReadOnlySpan<byte> message, ref int offset, int count)
        {
            EnsureAvailable(message, offset, count);
            offset += count;
        }

        private static void EnsureAvailable(ReadOnlySpan<byte> message, int offset, int count)
        {
            if (offset < 0 || count < 0 || offset > message.Length - count)
                throw new InvalidDataException("Truncated DNS message.");
        }
    }

    private readonly record struct Resolution(string Name, IPAddress Address, int Ttl);
}
