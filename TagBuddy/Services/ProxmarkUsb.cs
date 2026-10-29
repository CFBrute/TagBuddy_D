#if ANDROID
using Android.App;
using Android.Content;
using Android.Hardware.Usb;

namespace TagBuddy.Services;

/// <summary>Experimental: talks to a Proxmark3 attached by USB-OTG. The Proxmark enumerates as a USB-CDC serial
/// device (vendor 0x9AC4). This opens that serial interface over Android's USB-Host API and sends the Proxmark's
/// own "NG" framed ping/version command, to prove whether the phone can speak to the device at all. It is a
/// diagnostic step toward a fuller client, not the client itself.</summary>
///
/// <remarks>
/// <para>The "NG" wire format (from the Proxmark3 source, <c>include/pm3_cmd.h</c>): a host→device command is an
/// 8-byte preamble — magic <c>0x61334D50</c> ("PM3a", little-endian so the bytes read 50 4D 33 61), then a
/// 16-bit field holding a 15-bit length with the top bit set to mean "NG", then the 16-bit command — followed by
/// the data and a 2-byte postamble. Over USB the link is reliable, so the postamble carries the magic
/// <c>0x3361</c> ("a3") in place of a real CRC and the device does not check it. A device→host response mirrors
/// this with magic <c>0x62334D50</c> ("PM3b"); seeing that header back is the proof the two can talk.</para>
/// </remarks>
public sealed class ProxmarkUsb
{
    /// <summary>Vendor ids a Proxmark3 enumerates with: 0x9AC4 (proxmark.org / RDV4 / the community firmware's
    /// signed descriptor) and 0x2D2D (the Proxmark3 Easy, product 0x504D = "PM").</summary>
    public static readonly int[] VendorIds = [0x9AC4, 0x2D2D];

    private static bool IsProxmark(UsbDevice d) => Array.IndexOf(VendorIds, d.VendorId) >= 0;

    private const string PermissionAction = "com.barcodebuddy.app.USB_PERMISSION";

    // Command ids, from include/pm3_cmd.h.
    private const ulong CmdVersion = 0x0107;
    private const ulong CmdPing = 0x0109;
    private const ulong CmdDebugPrintString = 0x0100;
    private const ulong CmdAck = 0x00ff;
    private const ulong CmdHf14aReader = 0x0385;    // CMD_READER_ISO_14443a
    private const ulong CmdMagicGetBlock = 0x0606;  // CMD_MIFARE_CGETBLOCK (gen1a backdoor read)
    private const ulong CmdMagicSetBlock = 0x0605;  // CMD_MIFARE_CSETBLOCK (gen1a backdoor write)

    // Authenticated (keyed) MIFARE Classic, verified against Proxmark/proxmark3 master (the OLD protocol). These
    // need a known key per sector; the firmware sends a DEBUG_PRINT_STRING before the real ACK (see ReadToAck).
    private const ulong CmdMifareReadBlock = 0x0620;  // CMD_MIFARE_READBL: arg0=block, arg1=keyType(0=A,1=B), key=data[0..5]
    private const ulong CmdMifareNested = 0x0612;     // CMD_MIFARE_NESTED: collect encrypted nonces for the nested attack

    // ISO14A_COMMAND flags (include/mifare.h). OLD firmware takes these as arg0 of the reader command.
    private const ulong Iso14aConnect = 0x0001;
    private const ulong Iso14aNoDisconnect = 0x0002;

    // Magic-card work flags (armsrc/mifarecmd.c): WUPC|HALT|INIT|OFF = a single backdoor operation on a gen1a card.
    private const ulong MagicSingle = 0x1E;

    /// <summary>Block 0 is 16 bytes: a 4-byte UID card holds UID(4) + BCC(1) + SAK(1) + ATQA(2) + manufacturer(8),
    /// where BCC is the XOR of the four UID bytes.</summary>
    public const int BlockSize = 16;

    public static byte Bcc4(ReadOnlySpan<byte> uid4) => (byte)(uid4[0] ^ uid4[1] ^ uid4[2] ^ uid4[3]);

    // This Proxmark3 Easy firmware speaks the OLD protocol: a fixed 544-byte frame — a 64-bit command, then three
    // 64-bit args, then 512 data bytes, all little-endian, with no magic. (The newer "NG" framing got back an
    // "unknown command" reply, which is how we learned the firmware is OLD-only.) OLD commands are also accepted
    // by newer firmware, so sending OLD is the safe choice across versions.
    private const int OldFrameSize = 544;

    /// <summary>Raised step by step as a connection is attempted, so the page can show progress. Lines may arrive
    /// on a background thread.</summary>
    public event Action<string>? Log;
    private void Say(string line) => Log?.Invoke(line);

    private static UsbManager? Manager =>
        Android.App.Application.Context?.GetSystemService(Context.UsbService) as UsbManager;

    /// <summary>A Proxmark (any device from its vendor) currently attached, or null.</summary>
    public static UsbDevice? Attached()
    {
        var list = Manager?.DeviceList;
        if (list is null) return null;
        foreach (var d in list.Values)
            if (IsProxmark(d)) return d;
        return null;
    }

    /// <summary>True when something that looks like a Proxmark is plugged in right now.</summary>
    public static bool IsAttached() => Attached() is not null;

    /// <summary>Any connected USB device that looks like it could be a serial port (has a bulk IN/OUT pair), preferring
    /// a real Proxmark by vendor id. Used by the "try the connected device anyway" path, for a Proxmark clone or a
    /// board that enumerates under a vendor id we do not list.</summary>
    public static UsbDevice? AnyUsbCandidate()
    {
        var list = Manager?.DeviceList;
        if (list is null) return null;
        foreach (var d in list.Values) if (IsProxmark(d)) return d;
        foreach (var d in list.Values) if (HasBulkPair(d)) return d;
        return null;
    }

    /// <summary>A USB device is connected that we did not recognise as a Proxmark by its vendor id, but which could be
    /// one (a clone, or an unusual descriptor). The page offers to try talking to it.</summary>
    public static bool ForeignUsbPresent() => !IsAttached() && AnyUsbCandidate() is not null;

    private static bool HasBulkPair(UsbDevice d)
    {
        for (int i = 0; i < d.InterfaceCount; i++)
        {
            var intf = d.GetInterface(i);
            bool bin = false, bout = false;
            for (int e = 0; e < intf.EndpointCount; e++)
            {
                var ep = intf.GetEndpoint(e);
                if (ep is null || ep.Type != UsbAddressing.XferBulk) continue;
                if (ep.Direction == UsbAddressing.In) bin = true; else bout = true;
            }
            if (bin && bout) return true;
        }
        return false;
    }

    /// <summary>When set, a command may open a connected USB device that is not a recognised Proxmark (see
    /// <see cref="AnyUsbCandidate"/>). Off by default, so only known Proxmarks are touched without the person asking.</summary>
    public bool AllowAnyDevice { get; set; }

    /// <summary>The device a command should use: a recognised Proxmark, or (when <see cref="AllowAnyDevice"/> is set)
    /// any serial-like USB device that is connected.</summary>
    private UsbDevice? ResolveDevice() => Attached() ?? (AllowAnyDevice ? AnyUsbCandidate() : null);

    /// <summary>Whether the device answered the newer "NG" framing on the last <see cref="DeviceInfoAsync"/>. When
    /// true the firmware is a modern build (Iceman/RRG); the OLD framing is still used for operations, since newer
    /// firmware accepts it too.</summary>
    public bool SpeaksNg { get; private set; }

    // --- auto-open: MainActivity notes a USB-attach intent, the shell navigates here on the next chance ---

    /// <summary>Raised when a Proxmark is plugged in or unplugged, so the shell can show or hide the RF tab. The
    /// handler should re-check <see cref="IsAttached"/> rather than trust the event, since events can be missed.</summary>
    public static event Action? PresenceChanged;

    /// <summary>Set when an attach arrived before the shell could act on it, so the RF tab can be opened on show.</summary>
    public static bool PendingAttach { get; private set; }

    public static void NoteAttached()
    {
        PendingAttach = true;
        PresenceChanged?.Invoke();
    }

    public static void NoteDetached()
    {
        PendingAttach = false;
        CloseLink();
        PresenceChanged?.Invoke();
    }

    public static void ClearPending() => PendingAttach = false;

    // --- the persistent connection: opened once while the Proxmark is attached and reused for every command ---
    // Opening and closing the CDC serial for each command left the write endpoint dead after the first use, so the
    // link is kept open and shared (guarded by _gate) until the device is unplugged.

    private static readonly object _gate = new();
    private static Link? _link;
    private static int _linkDeviceId = -1;

    private static void CloseLink()
    {
        lock (_gate)
        {
            _link?.Dispose();
            _link = null;
            _linkDeviceId = -1;
        }
    }

    /// <summary>Ensures the shared link is open to the attached Proxmark, asks permission if needed, then runs
    /// <paramref name="action"/> on it under the lock, returning <paramref name="onFail"/> if the link can't open.
    /// A hard USB failure drops the link so the next call reopens.</summary>
    private async Task<T> WithLinkAsync<T>(Func<Link, T> action, T onFail)
    {
        var mgr = Manager;
        var device = ResolveDevice();
        if (mgr is null || device is null) { Say("No Proxmark connected."); return onFail; }
        if (!mgr.HasPermission(device) && !await RequestPermissionAsync(mgr, device)) { Say("Permission was denied."); return onFail; }

        return await Task.Run(() =>
        {
            lock (_gate)
            {
                if (_link is null || _linkDeviceId != device.DeviceId)
                {
                    _link?.Dispose();
                    _link = Open(mgr, device);
                    _linkDeviceId = _link is null ? -1 : device.DeviceId;
                    if (_link is not null) Say("Connected to the Proxmark.");
                }
                if (_link is null) return onFail;

                try { return action(_link); }
                catch (Java.IO.IOException ex) { Say($"USB I/O error: {ex.Message}"); CloseLink(); return onFail; }
                catch (Exception ex) { Say($"Unexpected error: {ex.Message}"); CloseLink(); return onFail; }
            }
        });
    }

    /// <summary>Asks the Proxmark for its version over the shared link, reporting through <see cref="Log"/>. Returns
    /// true when the device replied (the link works).</summary>
    public Task<bool> ProbeAsync() => WithLinkAsync(Probe, false);

    private Task<bool> RequestPermissionAsync(UsbManager mgr, UsbDevice device)
    {
        var tcs = new TaskCompletionSource<bool>();
        var context = Android.App.Application.Context;
        var receiver = new PermissionReceiver(granted => tcs.TrySetResult(granted));

        var filter = new IntentFilter(PermissionAction);
        if (OperatingSystem.IsAndroidVersionAtLeast(33))
            context.RegisterReceiver(receiver, filter, ReceiverFlags.NotExported);
        else
            context.RegisterReceiver(receiver, filter);
        receiver.Unregister = () => { try { context.UnregisterReceiver(receiver); } catch { /* already gone */ } };

        // USB permission needs the system to fill in the device extra, so the PendingIntent must be mutable. The
        // explicit Mutable flag exists only on API 31+; below that a PendingIntent is mutable by default anyway.
        var intent = new Intent(PermissionAction).SetPackage(context.PackageName);
        var flags = OperatingSystem.IsAndroidVersionAtLeast(31) ? PendingIntentFlags.Mutable : PendingIntentFlags.UpdateCurrent;
        var pending = PendingIntent.GetBroadcast(context, 0, intent, flags);
        mgr.RequestPermission(device, pending);
        return tcs.Task;
    }

    private bool Probe(Link link)
    {
        var reply = Command(link, CmdVersion, readTimeoutMs: 2000, what: "version request");
        if (reply.Length == 0)
        {
            Say("No reply. The port is open but the Proxmark sent nothing back — it may need external power over OTG.");
            return false;
        }

        string text = AsciiRun(reply);
        Say("✓ The Proxmark replied — this phone CAN talk to the device.");
        Say($"Reply command: 0x{ReplyCmd(reply):X}.");
        if (text.Length > 3) Say($"Text: {text}");
        return true;
    }

    /// <summary>Asks the device for its firmware version (OLD framing, which every firmware accepts) and then tries the
    /// newer "NG" framing too, to learn whether this is a modern (Iceman/RRG) build. Reports both through the log and
    /// sets <see cref="SpeaksNg"/>. Returns true when the device answered at all.</summary>
    public Task<bool> DeviceInfoAsync() => WithLinkAsync(DeviceInfo, false);

    private bool DeviceInfo(Link link)
    {
        // OLD version: the banner text (firmware name, build, bootrom) lives in the reply's data area.
        var oldReply = Command(link, CmdVersion, readTimeoutMs: 2000, what: "version request");
        if (oldReply.Length == 0)
        {
            Say("No reply to the version request — the port is open but the device sent nothing (it may need external power over OTG).");
            return false;
        }
        var banner = AsciiRun(oldReply);
        foreach (var line in banner.Split(new[] { "  ", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            if (line.Trim().Length > 4) Say(line.Trim());

        // NG version: a modern firmware answers with the "PM3b" magic; an OLD-only firmware ignores it or NAKs.
        Drain(link.Conn, link.In);
        var ngReq = NgFrame(0x0107, []);   // CMD_VERSION in NG framing
        bool ngOk = link.Conn.BulkTransfer(link.Out, ngReq, ngReq.Length, 1000) >= 0
                    && ContainsPm3b(ReadReply(link.Conn, link.In, 1500));
        SpeaksNg = ngOk;
        Say(ngOk
            ? "Protocol: newer (NG) framing is supported — this is a modern firmware (Iceman/RRG). Operations still use the compatible OLD framing."
            : "Protocol: OLD framing only — operations use it (and it is accepted by newer firmware too).");
        return true;
    }

    /// <summary>Builds a host→device NG frame: 4-byte "PM3a" magic, a 15-bit length with the NG bit set, the 16-bit
    /// command, the data, and a 2-byte postamble magic (the link is reliable over USB, so no real CRC is needed).</summary>
    private static byte[] NgFrame(ushort cmd, byte[] data)
    {
        int len = data?.Length ?? 0;
        var f = new byte[8 + len + 2];
        BitConverter.TryWriteBytes(f.AsSpan(0), 0x61334D50u);          // "PM3a"
        BitConverter.TryWriteBytes(f.AsSpan(4), (ushort)((len & 0x7FFF) | 0x8000));   // length | NG bit
        BitConverter.TryWriteBytes(f.AsSpan(6), cmd);
        if (len > 0) Array.Copy(data!, 0, f, 8, len);
        BitConverter.TryWriteBytes(f.AsSpan(8 + len), (ushort)0x3361);  // COMMANDNG_POSTAMBLE_MAGIC
        return f;
    }

    /// <summary>Whether a reply carries the NG response magic "PM3b" (0x62334D50, bytes 50 4D 33 62), the proof that
    /// the device understood the NG framing.</summary>
    private static bool ContainsPm3b(byte[] reply)
    {
        for (int i = 0; i + 4 <= reply.Length; i++)
            if (reply[i] == 0x50 && reply[i + 1] == 0x4D && reply[i + 2] == 0x33 && reply[i + 3] == 0x62) return true;
        return false;
    }

    /// <summary>Reads a block through the gen1a magic backdoor (block 0 is the UID block). Returns the 16 bytes, or
    /// null if the card isn't a gen1a magic card or no card coupled.</summary>
    public Task<byte[]?> MagicReadBlockAsync(int blockNo) => WithLinkAsync(link => MagicReadBlock(link, blockNo), null);

    /// <summary>Writes 16 bytes to a block through the gen1a magic backdoor, then reads it back to verify. Returns
    /// the verified bytes on success, or null on failure.</summary>
    public Task<byte[]?> MagicWriteBlockAsync(int blockNo, byte[] block16) => WithLinkAsync(link => MagicWriteBlock(link, blockNo, block16), null);

    /// <summary>Writes several full blocks to a gen1a magic tag through the backdoor (data, trailers/keys, block 0 —
    /// anything), in one coupling session. Returns true only if every block was written.</summary>
    public Task<bool> MagicWriteBlocksAsync(IReadOnlyDictionary<int, byte[]> blocks) => WithLinkAsync(link => MagicWriteBlocks(link, blocks), false);

    private bool MagicWriteBlocks(Link link, IReadOnlyDictionary<int, byte[]> blocks)
    {
        if (blocks.Count == 0) { Say("Nothing to write."); return false; }
        if (!WaitForCard(link)) { Say("No tag on the antenna. Hold the tag flat on the coil and try again."); return false; }

        int done = 0;
        foreach (var (block, data) in blocks.OrderBy(b => b.Key))
        {
            if (data.Length != BlockSize) { Say($"blk {block}: not {BlockSize} bytes, skipped."); continue; }
            var reply = Command(link, CmdMagicSetBlock, 0, MagicSingle, (ulong)block, data, readTimeoutMs: 2000, what: "write command");
            if (IsOkAck(reply)) { done++; Say($"blk {block}: written"); }
            else { Say($"blk {block}: write FAILED (cmd 0x{ReplyCmd(reply):X})"); }
        }
        Say($"Wrote {done} of {blocks.Count} blocks.");
        return done == blocks.Count;
    }

    /// <summary>Polls the HF reader until a card couples (the gen1a card's antenna is weak, so a read often misses).</summary>
    private bool WaitForCard(Link link, int tries = 40)
    {
        for (int i = 0; i < tries; i++)
            if (ReplyArg(Command(link, CmdHf14aReader, Iso14aConnect, readTimeoutMs: 500, what: "read command")) >= 1) return true;
        return false;
    }

    private byte[]? MagicReadBlock(Link link, int blockNo)
    {
        if (!WaitForCard(link)) { Say("No tag on the antenna. Hold a tag flat on the Proxmark's coil and try again."); return null; }
        var block = MagicReadBlockRaw(link, blockNo, MagicSingle);
        if (block is null) Say("That tag isn't a gen1a magic card — it has no UID backdoor.");
        return block;
    }

    /// <summary>One CGETBLOCK, assuming the card is already coupled. <paramref name="workFlags"/> is MagicSingle for a
    /// standalone read, or a field-on sequence for a dump. Returns the 16 block bytes, or null on any failure.</summary>
    private byte[]? MagicReadBlockRaw(Link link, int blockNo, ulong workFlags)
    {
        // CGETBLOCK: arg0 = work flags, arg2 = block number (arg1 unused).
        var reply = Command(link, CmdMagicGetBlock, workFlags, 0, (ulong)blockNo, what: "read command");
        return IsOkAck(reply) ? ReplyData(reply, BlockSize) : null;
    }

    /// <summary>A card read over the Proxmark: its 14443-A identity and, for a magic card, every block.</summary>
    public sealed record Dump(byte[] Uid, byte[] Atqa, byte Sak, IReadOnlyDictionary<int, byte[]> Blocks)
    {
        public bool IsMagic => Blocks.Count > 0;
    }

    /// <summary>Reads the card on the antenna: its identity always, and (if it's a gen1a magic card) a full block
    /// dump through the backdoor — no keys needed. Returns null if nothing coupled.</summary>
    public Task<Dump?> ReadCardAsync() => WithLinkAsync(ReadCard, null);

    private Dump? ReadCard(Link link)
    {
        if (ReadIdentity(link) is not { } id)
        {
            Say("No tag on the antenna. Hold a tag flat on the Proxmark's coil and try again.");
            return null;
        }
        var (uid, atqa, sak) = id;
        Say($"Tag {string.Join(":", uid.Select(b => b.ToString("X2")))}  ·  SAK {sak:X2}");

        // Probe the backdoor with block 0. If it answers, the tag is a gen1a magic card — dump every block.
        int count = sak == 0x18 ? 256 : 64;   // 4K vs 1K
        var blocks = new Dictionary<int, byte[]>();
        var b0 = MagicReadBlockRaw(link, 0, 0x0A);  // INIT|WUPC: field on + unlock, held open
        if (b0 is null)
        {
            Say("Not a gen1a magic tag — showing its identity only (reading its data would need the tag's keys).");
            return new Dump(uid, atqa, sak, blocks);
        }

        blocks[0] = b0;
        for (int b = 1; b < count; b++)
        {
            ulong wf = b == count - 1 ? 0x14UL : 0x00UL;   // last block HALT|OFF, the rest keep the field on
            if (MagicReadBlockRaw(link, b, wf) is { } data) blocks[b] = data;
            if (b % 16 == 0) Say($"read {blocks.Count}/{count} blocks…");
        }
        Say($"Read {blocks.Count} of {count} blocks.");
        return new Dump(uid, atqa, sak, blocks);
    }

    /// <summary>Polls the HF reader until a card couples, returning its UID/ATQA/SAK (null if none in time).</summary>
    private (byte[] Uid, byte[] Atqa, byte Sak)? ReadIdentity(Link link, int tries = 40)
    {
        for (int i = 0; i < tries; i++)
        {
            var reply = Command(link, CmdHf14aReader, Iso14aConnect, readTimeoutMs: 500, what: "read command");
            if (IsOkAck(reply) && reply.Length >= 32 + 14)
            {
                var d = reply.AsSpan(32);
                int uidlen = Math.Clamp((int)d[10], 0, 10);
                return (d.Slice(0, uidlen).ToArray(), d.Slice(11, 2).ToArray(), d[13]);
            }
        }
        return null;
    }

    /// <summary>A quick look for an HF tag on the antenna (one or two tries, no waiting): its UID as a colon-hex
    /// string, or null when nothing is there. For the auto-reader's polling loop.</summary>
    public Task<string?> PeekHfAsync() => WithLinkAsync(link =>
        ReadIdentity(link, tries: 2) is { } id ? string.Join(":", id.Uid.Select(b => b.ToString("X2"))) : null, null);

    private byte[]? MagicWriteBlock(Link link, int blockNo, byte[] block16)
    {
        if (block16.Length != BlockSize) { Say($"A block is {BlockSize} bytes."); return null; }
        if (!WaitForCard(link)) { Say("No tag on the antenna. Hold the tag flat on the coil and try again."); return null; }

        // CSETBLOCK: arg0 = needWipe (0), arg1 = work flags, arg2 = block number; data = the 16 bytes.
        var reply = Command(link, CmdMagicSetBlock, 0, MagicSingle, (ulong)blockNo, block16, readTimeoutMs: 2000, what: "write command");
        if (!IsOkAck(reply))
        {
            Say(AsciiRun(reply).Contains("wupC1")
                ? "Write failed: that tag isn't a gen1a magic card."
                : $"Write failed (cmd 0x{ReplyCmd(reply):X}, arg0 {ReplyArg(reply)}).");
            return null;
        }

        // Read the block back so the caller can confirm it took (card is already coupled).
        var check = MagicReadBlockRaw(link, blockNo, MagicSingle);
        if (check is null) { Say("Wrote the block but could not read it back to verify."); return null; }
        return check;
    }


    // ------------------------------------------------------------------------------------------------ LF (125 kHz)
    //
    // Verified end-to-end on a device (2016 Easy firmware): acquire/download ids are correct, DemodEm410x decodes a
    // real EM4100 (run-length half-bit detection), and the T55xx write clones an EM410x id onto a T5577 that reads
    // back — once the two write bugs were fixed (command id 0x0215, and the config block written LAST).
    //
    // EXPERIMENTAL and unverified on a device. LF is not like HF: the phone cannot reach 125 kHz at all, so every
    // byte here goes through the Proxmark. A read ACQUIREs raw ADC samples into the device's big buffer, downloads
    // them, and demodulates EM410x (the common door-fob format) on the phone. A write clones an EM410x id onto a
    // T5577 (the common rewritable LF card). The OLD command ids below are the pre-NG values; if a given firmware
    // numbers them differently the log will show no ack, which is the signal to adjust them.

    private const ulong CmdLfAcquireRaw125k = 0x0205;     // CMD_ACQUIRE_RAW_ADC_SAMPLES_125K
    private const ulong CmdLfDownloadRaw125k = 0x0207;    // CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K (request)
    private const ulong CmdLfDownloadedRaw125k = 0x0208;  // CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K (each reply frame)
    private const ulong CmdLfT55xxWriteBlock = 0x0215;    // CMD_T55XX_WRITE_BLOCK

    /// <summary>A 125 kHz read: the raw samples captured, and the EM410x id if one demodulated.</summary>
    public sealed record LfRead(int SampleCount, ulong? Em410xId, byte[] Samples)
    {
        public string? IdHex => Em410xId is { } v ? v.ToString("X10") : null;

        /// <summary>A tag is on the antenna (the field is modulated), even if no id decoded.</summary>
        public bool SignalPresent { get; init; }
    }

    /// <summary>Captures 125 kHz samples over the Proxmark and tries to read an EM410x id from them. Returns the
    /// result (id may be null when nothing demodulated), or null if the device did not answer.</summary>
    public Task<LfRead?> LfReadAsync(int maxSamples = 20000) => WithLinkAsync(link => ReadLf(link, maxSamples), null);

    private LfRead? ReadLf(Link link, int maxSamples)
    {
        Say("Acquiring 125 kHz samples (hold the LF tag on the Proxmark's LF antenna)…");
        Command(link, CmdLfAcquireRaw125k, writeTimeoutMs: 1500, readTimeoutMs: 3000, what: "acquire command");   // its ack carries the sample count

        var samples = DownloadRaw(link, maxSamples);
        Say($"Captured {samples.Length} samples.");
        if (samples.Length < 128)
        {
            Say("Too few samples — the LF antenna may not be powered, or the command id differs on this firmware.");
            return new LfRead(samples.Length, null, samples);
        }

        bool present = HasModulation(samples);
        var id = DemodEm410x(samples);
        if (id is { } v) Say($"EM410x id: {v:X10}");
        else if (present) Say("An LF tag is on the antenna (the field is modulated), but no EM410x id decoded — it may be another format (HID, Indala…) or coupling too weakly.");
        else Say("No LF signal — is a tag on the antenna?");
        return new LfRead(samples.Length, id, samples) { SignalPresent = present };
    }

    /// <summary>True when the capture is a modulated carrier (a tag on the antenna) rather than a flat, quiet field:
    /// a 125 kHz tag swings the level widely and crosses the mean many times.</summary>
    private static bool HasModulation(byte[] s)
    {
        if (s.Length < 256) return false;
        double mean = 0; foreach (var x in s) mean += x; mean /= s.Length;
        int min = 255, max = 0, trans = 0; bool prev = s[0] >= mean;
        foreach (var x in s) { if (x < min) min = x; if (x > max) max = x; bool h = x >= mean; if (h != prev) trans++; prev = h; }
        return max - min > 48 && trans > 40;
    }

    /// <summary>Downloads up to <paramref name="maxBytes"/> of the device's captured sample buffer, one OLD frame at a
    /// time (each carries an offset, a length and up to 512 bytes of samples).</summary>
    private byte[] DownloadRaw(Link link, int maxBytes)
    {
        var outp = new List<byte>(maxBytes);
        Send(link, CmdLfDownloadRaw125k, 0, (ulong)maxBytes, what: "download command");

        // Leftover frames from the acquire (debug strings, its ack) can arrive before the sample frames, so skip any
        // non-sample frame until the samples start; once they have, a non-sample frame is the final ack = done.
        bool started = false;
        int idle = 0;
        while (outp.Count < maxBytes)
        {
            var f = ReadReply(link.Conn, link.In, 1500);
            if (f.Length < 32)
            {
                if (started || ++idle >= 3) break;   // no more data
                continue;
            }
            if (ReplyCmd(f) != CmdLfDownloadedRaw125k)
            {
                if (started) break;                  // the trailing ack: done
                continue;                            // a leftover acquire frame before the samples: skip it
            }
            started = true;
            // arg1 is this frame's byte count; the samples follow in the data area.
            int n = Math.Min(Math.Min((int)ReplyArg(f, 1), f.Length - 32), 512);
            if (n <= 0) break;
            for (int i = 0; i < n; i++) outp.Add(f[32 + i]);
        }
        return outp.ToArray();
    }

    /// <summary>Best-effort EM410x demodulation of raw 125 kHz samples: centre the signal, find the half-bit length
    /// from the shortest run, sample to bits, Manchester-decode, then locate the 64-bit EM410x frame (9-bit header,
    /// 10 rows of 4 data + row parity, 4 column parities, stop bit) and return its 40-bit id. Null if none is found.</summary>
    private static ulong? DemodEm410x(byte[] raw)
    {
        // Skip the field/AGC settling at the very start of the capture.
        int skip = Math.Min(200, raw.Length / 10);
        int n = raw.Length - skip;
        if (n < 256) return null;
        var samples = new byte[n];
        Array.Copy(raw, skip, samples, 0, n);

        // Samples are unsigned ADC bytes around a DC level; centre on the mean so a simple sign gives the bit level.
        double mean = 0; for (int i = 0; i < n; i++) mean += samples[i]; mean /= n;
        var hi = new bool[n];
        for (int i = 0; i < n; i++) hi[i] = samples[i] >= mean;

        // Runs of a constant level, then the half-bit length from the dominant *short* run cluster. Using the
        // absolute shortest run (as before) made one noise glitch set the bit length wrong and nothing decoded.
        var runLevel = new List<bool>(); var runLen = new List<int>();
        int run = 1;
        for (int i = 1; i < n; i++) { if (hi[i] == hi[i - 1]) run++; else { runLevel.Add(hi[i - 1]); runLen.Add(run); run = 1; } }
        runLevel.Add(hi[n - 1]); runLen.Add(run);
        if (runLen.Count < 20) return null;

        var histo = new Dictionary<int, int>();
        foreach (var r in runLen) if (r >= 3) histo[r] = histo.GetValueOrDefault(r) + 1;
        if (histo.Count == 0) return null;
        int maxCount = histo.Values.Max();
        int minCommon = histo.Where(kv => kv.Value >= maxCount / 4).Select(kv => kv.Key).DefaultIfEmpty(0).Min();
        if (minCommon < 3) return null;
        double hnum = 0, hden = 0;
        foreach (var kv in histo) if (kv.Value >= maxCount / 4 && kv.Key < minCommon * 1.5) { hnum += (double)kv.Key * kv.Value; hden += kv.Value; }
        if (hden == 0) return null;
        double half = hnum / hden;           // samples per half-bit
        if (half < 3) return null;

        // Turn each run into whole half-bits (run≈half → 1, run≈2·half → 2). Robust to the ±1 jitter in run length;
        // fixed-step sampling drifted into bit errors over a 64-bit frame.
        var bits = new List<bool>();
        for (int i = 0; i < runLen.Count; i++)
        {
            int c = Math.Max(1, (int)Math.Round(runLen[i] / half));
            for (int k = 0; k < c; k++) bits.Add(runLevel[i]);
        }

        // Manchester: each bit is a 01 or 10 pair of half-bits. Try both phase alignments and look for a valid frame.
        for (int phase = 0; phase < 2; phase++)
        {
            var decoded = new List<int>(bits.Count / 2);
            bool ok = true;
            for (int i = phase; i + 1 < bits.Count; i += 2)
            {
                if (!bits[i] && bits[i + 1]) decoded.Add(0);
                else if (bits[i] && !bits[i + 1]) decoded.Add(1);
                else { ok = false; break; }   // 00 or 11: a glitch or wrong phase
            }
            if (ok && Em410xFromBits(decoded) is { } id) return id;
        }
        return null;
    }

    /// <summary>Finds the EM410x frame in a run of decoded bits and returns its 40-bit id, checking the row and
    /// column parities. Null when no valid frame is present.</summary>
    private static ulong? Em410xFromBits(List<int> b)
    {
        // Slide a 64-bit window looking for the 9-bit all-ones header.
        for (int s = 0; s + 64 <= b.Count; s++)
        {
            bool header = true;
            for (int i = 0; i < 9; i++) if (b[s + i] != 1) { header = false; break; }
            if (!header) continue;

            ulong id = 0;
            var cols = new int[4];
            bool good = true;
            int p = s + 9;
            for (int row = 0; row < 10 && good; row++)
            {
                int parity = 0;
                for (int c = 0; c < 4; c++)
                {
                    int bit = b[p++];
                    parity ^= bit;
                    cols[c] ^= bit;
                    id = (id << 1) | (ulong)bit;
                }
                if (b[p++] != parity) good = false;   // row parity (even)
            }
            if (!good) continue;
            bool colsOk = true;
            for (int c = 0; c < 4; c++) if (b[p++] != cols[c]) { colsOk = false; break; }
            if (colsOk && b[p] == 0) return id;        // trailing stop bit is 0
        }
        return null;
    }

    /// <summary>Clones an EM410x id onto a T5577 card on the LF antenna: writes the EM config block and the two data
    /// blocks that hold the encoded id. No password and no lock bits are set, so the card can always be rewritten.
    /// Returns true if every block was acknowledged.</summary>
    public Task<bool> LfWriteEm410xAsync(ulong id40) => WithLinkAsync(link => LfWriteEm410x(link, id40), false);

    private bool LfWriteEm410x(Link link, ulong id40)
    {
        var (config, b1, b2) = EncodeEm410xT55xx(id40);
        Say($"Writing EM410x {id40 & 0xFFFFFFFFFF:X10} to a T5577 (config {config:X8}, data {b1:X8} {b2:X8})…");
        // Data blocks first, config block LAST: writing the config first leaves the chip at its old bit rate and the
        // new data never reads back (verified on a device — config-last is what makes the clone take).
        bool ok = T55xxWrite(link, 1, b1) && T55xxWrite(link, 2, b2) && T55xxWrite(link, 0, config);
        Say(ok ? "All three blocks acknowledged. Re-read the card to confirm the id." : "A block was not acknowledged — see above.");
        return ok;
    }

    private bool T55xxWrite(Link link, int block, uint data)
    {
        // OLD T55xx write: arg0 = data, arg1 = block, arg2 = password (0, and no password flag set).
        var reply = Command(link, CmdLfT55xxWriteBlock, data, (ulong)block, 0, writeTimeoutMs: 1500, readTimeoutMs: 2000, what: "T55xx write");
        // The firmware does not always ack a T55xx write; treat any reply, or none, as "sent" and rely on a re-read.
        Say($"blk {block}: sent (reply cmd 0x{ReplyCmd(reply):X}).");
        return true;
    }

    /// <summary>Encodes a 40-bit EM410x id into the T5577 config word and two 32-bit data blocks: the 64-bit EM410x
    /// frame (9-bit header, row/column parities, stop bit) split across blocks 1 and 2, with the standard EM config
    /// (ASK, Manchester, RF/64, two data blocks).</summary>
    private static (uint Config, uint Block1, uint Block2) EncodeEm410xT55xx(ulong id40)
    {
        ulong frame = 0;
        for (int i = 0; i < 9; i++) frame = (frame << 1) | 1;   // 9-bit header of ones
        var cols = new int[4];
        for (int row = 0; row < 10; row++)
        {
            int nibble = (int)((id40 >> ((9 - row) * 4)) & 0xF);
            int parity = 0;
            for (int bit = 3; bit >= 0; bit--)
            {
                int v = (nibble >> bit) & 1;
                parity ^= v;
                cols[3 - bit] ^= v;
                frame = (frame << 1) | (ulong)v;
            }
            frame = (frame << 1) | (ulong)parity;   // even row parity
        }
        for (int c = 0; c < 4; c++) frame = (frame << 1) | (ulong)cols[c];   // column parities
        frame <<= 1;                                 // stop bit 0

        const uint config = 0x00148040;              // EM410x: ASK, Manchester, RF/64, 2 data blocks
        return (config, (uint)(frame >> 32), (uint)(frame & 0xFFFFFFFF));
    }

    // ------------------------------------------------------------------------------------------------ keyed MIFARE + nested
    //
    // EXPERIMENTAL and unverified in the app (proven on the spike, see TODO-proxmark-key-recovery.md). These use a
    // known key, so they read ordinary (non-magic) Classic cards, and collect the encrypted nonces the Crypto1
    // nested attack needs. The key RECOVERY itself (Crypto1.Nonce2Key) is not yet confirmed — see Crypto1.cs.

    /// <summary>Reads a window of replies and returns the frame that is the real CMD_ACK, surfacing any
    /// DEBUG_PRINT_STRING frames the firmware sends first (e.g. "Auth error") through the log.</summary>
    private byte[]? ReadToAck(Link link, int totalTimeoutMs)
    {
        var all = new List<byte>();
        var buf = new byte[1024];
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < totalTimeoutMs)
        {
            int n = link.Conn.BulkTransfer(link.In, buf, buf.Length, 250);
            if (n > 0) all.AddRange(buf[..n]);
            for (int off = 0; off + OldFrameSize <= all.Count; off += OldFrameSize)
                if (BitConverter.ToUInt64(all.ToArray(), off) == CmdAck) goto done;
        }
        done:
        var bytes = all.ToArray();
        for (int off = 0; off + OldFrameSize <= bytes.Length; off += OldFrameSize)
        {
            ulong c = BitConverter.ToUInt64(bytes, off);
            if (c == CmdDebugPrintString)
            {
                ulong len = BitConverter.ToUInt64(bytes, off + 8);
                var s = new string(bytes.Skip(off + 32).Take((int)Math.Min(len, 64))
                    .Where(x => x is >= 0x20 and < 0x7F).Select(x => (char)x).ToArray());
                if (s.Length > 0) Say($"[fw] {s}");
            }
            if (c == CmdAck) return bytes.AsSpan(off, OldFrameSize).ToArray();
        }
        return null;
    }

    private static byte[] KeyData(byte[] key6)
    {
        var d = new byte[512];
        Array.Copy(key6, 0, d, 0, Math.Min(6, key6.Length));
        return d;
    }

    /// <summary>Reads one block of a real MIFARE Classic card with a known key. Returns the 16 bytes, or null when
    /// the key does not open the sector or the card moved away.</summary>
    public Task<byte[]?> MifareReadBlockAsync(int block, bool keyB, byte[] key6) =>
        WithLinkAsync(link => MifareReadBlock(link, block, keyB, key6), null);

    private byte[]? MifareReadBlock(Link link, int block, bool keyB, byte[] key6)
    {
        Drain(link.Conn, link.In);
        var req = OldFrame(CmdMifareReadBlock, (ulong)block, keyB ? 1UL : 0UL, 0, KeyData(key6));
        if (link.Conn.BulkTransfer(link.Out, req, req.Length, 1000) < 0) throw new Java.IO.IOException("the read command could not be written");
        var ack = ReadToAck(link, 2000);
        if (ack is null || ReplyArg(ack) == 0) { Say($"block {block}: key {(keyB ? 'B' : 'A')} did not open it."); return null; }
        return ReplyData(ack, BlockSize);
    }

    /// <summary>The encrypted nonces one NESTED call collects, for recovering <see cref="TargetBlock"/>'s key.</summary>
    public sealed record NestedNonces(uint Cuid, uint Nt0, uint Ks0, uint Nt1, uint Ks1, int TargetBlock, bool TargetKeyB, uint AuthTimeout = 0, uint FixedNt = 0);

    /// <summary>Collects a pair of encrypted nonces for the nested attack: authenticates <paramref name="knownBlock"/>
    /// with a known key, then asks the card to authenticate <paramref name="targetBlock"/> and captures the nonces it
    /// sends. <paramref name="calibrate"/> should be true on the first call so the firmware measures the card timing.
    /// Returns null if the known key did not open its sector.</summary>
    public Task<NestedNonces?> MifareNestedAsync(int knownBlock, bool knownKeyB, byte[] knownKey, int targetBlock, bool targetKeyB, bool calibrate) =>
        WithLinkAsync(link => MifareNested(link, knownBlock, knownKeyB, targetBlock, targetKeyB, calibrate, knownKey), null);

    private NestedNonces? MifareNested(Link link, int knownBlock, bool knownKeyB, int targetBlock, bool targetKeyB, bool calibrate, byte[] knownKey)
    {
        // ARM arg layout (verified): arg0 = block | keyType<<8 (known), arg1 = target block | keyType<<8, arg2 = calibrate.
        ulong arg0 = (ulong)knownBlock | (knownKeyB ? 0x100UL : 0UL);
        ulong arg1 = (ulong)targetBlock | (targetKeyB ? 0x100UL : 0UL);
        Drain(link.Conn, link.In);
        var req = OldFrame(CmdMifareNested, arg0, arg1, calibrate ? 1UL : 0UL, KeyData(knownKey));
        if (link.Conn.BulkTransfer(link.Out, req, req.Length, 1000) < 0) throw new Java.IO.IOException("the nested command could not be written");

        var ack = ReadToAck(link, 4000);
        if (ack is null) { Say("Nested: no reply (the known key may not open its sector, or the card moved)."); return null; }
        // Reply data (28 bytes): cuid[0..3], nt0[4..7], ks0[8..11], nt1[12..15], ks1[16..19], timeout[20..23], fixed_nt[24..27].
        var d = ReplyData(ack, 28);
        if (d is null) { Say("Nested: reply too short to hold the nonce block."); return null; }
        uint U(int o) => (uint)(d[o] | d[o + 1] << 8 | d[o + 2] << 16 | d[o + 3] << 24);
        return new NestedNonces(U(0), U(4), U(8), U(12), U(16), targetBlock, targetKeyB, U(20), U(24));
    }

    /// <summary>An open, claimed, CDC-configured connection to the Proxmark; releasing it on dispose.</summary>
    private sealed class Link(UsbDeviceConnection conn, UsbEndpoint epIn, UsbEndpoint epOut, UsbInterface data, UsbInterface? comm) : IDisposable
    {
        public UsbDeviceConnection Conn { get; } = conn;
        public UsbEndpoint In { get; } = epIn;
        public UsbEndpoint Out { get; } = epOut;

        public void Dispose()
        {
            try { Conn.ReleaseInterface(data); } catch { }
            try { if (comm is not null) Conn.ReleaseInterface(comm); } catch { }
            Conn.Close();
        }
    }

    /// <summary>Opens the device, finds and claims the CDC serial interface, raises DTR/RTS and drains any startup
    /// chatter. Returns null (after logging why) if any step fails.</summary>
    private Link? Open(UsbManager mgr, UsbDevice device)
    {
        var conn = mgr.OpenDevice(device);
        if (conn is null) { Say("Could not open the device (OpenDevice returned nothing)."); return null; }

        UsbInterface? data = null, comm = null;
        for (int i = 0; i < device.InterfaceCount; i++)
        {
            var intf = device.GetInterface(i);
            if (intf.InterfaceClass == UsbClass.CdcData) data = intf;
            else if (intf.InterfaceClass == UsbClass.Comm) comm = intf;
        }
        data ??= FirstInterfaceWithBulk(device);
        if (data is null) { Say("No interface with bulk endpoints — not a USB serial device?"); conn.Close(); return null; }

        UsbEndpoint? epIn = null, epOut = null;
        for (int e = 0; e < data.EndpointCount; e++)
        {
            var ep = data.GetEndpoint(e);
            if (ep is null || ep.Type != UsbAddressing.XferBulk) continue;
            if (ep.Direction == UsbAddressing.In) epIn = ep; else epOut = ep;
        }
        if (epIn is null || epOut is null) { Say("The data interface has no bulk IN/OUT pair."); conn.Close(); return null; }

        if (comm is not null) conn.ClaimInterface(comm, true);
        if (!conn.ClaimInterface(data, true)) { Say("Could not claim the data interface."); conn.Close(); return null; }

        // CDC control: 115200 8N1 (ignored on a USB-virtual port, harmless) and raise DTR/RTS.
        int commIndex = comm?.Id ?? 0;
        var lineCoding = new byte[] { 0x00, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x08 };
        conn.ControlTransfer((UsbAddressing)0x21, 0x20, 0, commIndex, lineCoding, lineCoding.Length, 200);
        conn.ControlTransfer((UsbAddressing)0x21, 0x22, 0x03, commIndex, null, 0, 200);

        Drain(conn, epIn);
        return new Link(conn, epIn, epOut, data, comm);
    }

    private static UsbInterface? FirstInterfaceWithBulk(UsbDevice device)
    {
        for (int i = 0; i < device.InterfaceCount; i++)
        {
            var intf = device.GetInterface(i);
            for (int e = 0; e < intf.EndpointCount; e++)
                if (intf.GetEndpoint(e)?.Type == UsbAddressing.XferBulk) return intf;
        }
        return null;
    }

    /// <summary>Reads and discards everything the device still has queued, until the bus is quiet. A command such as
    /// version makes the Proxmark send many packets; if they are left unread its USB TX buffer stays full and it
    /// stops servicing our writes, so the next command's write times out. Draining first keeps the link healthy.</summary>
    private static void Drain(UsbDeviceConnection conn, UsbEndpoint epIn)
    {
        var buf = new byte[512];
        int quiet = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < 1500)
        {
            int n = conn.BulkTransfer(epIn, buf, buf.Length, 120);
            if (n > 0) quiet = 0;
            else if (++quiet >= 2) break;   // two quiet reads in a row: the backlog is cleared
        }
    }

    /// <summary>Reads from the bulk IN endpoint, accumulating until a lull or a full OLD frame, up to the timeout.</summary>
    private static byte[] ReadReply(UsbDeviceConnection conn, UsbEndpoint epIn, int totalTimeoutMs)
    {
        var all = new List<byte>();
        var buf = new byte[512];
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < totalTimeoutMs)
        {
            int n = conn.BulkTransfer(epIn, buf, buf.Length, 250);
            if (n > 0)
            {
                all.AddRange(buf[..n]);
                if (all.Count >= OldFrameSize) break;   // a whole OLD frame is in hand
            }
            else if (all.Count > 0)
            {
                break;   // got something, then a gap — that's the end of the reply
            }
        }
        return all.ToArray();
    }

    // --- one place for the drain → write → read → parse dance every command does over the OLD framing ---

    /// <summary>Writes one OLD-framed command (draining any backlog first, so the write is accepted). Throws when the
    /// write fails, naming the command with <paramref name="what"/>.</summary>
    private void Send(Link link, ulong cmd, ulong arg0 = 0, ulong arg1 = 0, ulong arg2 = 0, byte[]? data = null,
                      int timeoutMs = 1000, string what = "command")
    {
        // Drain, then write — retrying a couple of times. A long command (LF acquire) keeps trickling its reply out
        // after we've drained, and while the device is still sending it won't service our write; a drain-and-retry
        // lets the write land once that output finishes, instead of failing on the first attempt.
        var req = OldFrame(cmd, arg0, arg1, arg2, data);
        for (int attempt = 0; attempt < 3; attempt++)
        {
            Drain(link.Conn, link.In);
            if (link.Conn.BulkTransfer(link.Out, req, req.Length, timeoutMs) >= 0) return;
        }
        throw new Java.IO.IOException($"the {what} could not be written");
    }

    /// <summary>Sends one OLD-framed command and returns its reply (empty when none came in time).</summary>
    private byte[] Command(Link link, ulong cmd, ulong arg0 = 0, ulong arg1 = 0, ulong arg2 = 0, byte[]? data = null,
                           int writeTimeoutMs = 1000, int readTimeoutMs = 1500, string what = "command")
    {
        Send(link, cmd, arg0, arg1, arg2, data, writeTimeoutMs, what);
        return ReadReply(link.Conn, link.In, readTimeoutMs);
    }

    /// <summary>The command word of a reply frame (bytes 0-7), or 0 when the reply is too short.</summary>
    private static ulong ReplyCmd(byte[] r) => r.Length >= 8 ? BitConverter.ToUInt64(r, 0) : 0;

    /// <summary>Reply arg 0, 1 or 2 (the three 64-bit words after the command), or 0 when the reply is too short.</summary>
    private static ulong ReplyArg(byte[] r, int index = 0) => r.Length >= 16 + index * 8 ? BitConverter.ToUInt64(r, 8 + index * 8) : 0;

    /// <summary>A reply's data area (from byte 32) of the given length, or null when the reply is too short.</summary>
    private static byte[]? ReplyData(byte[] r, int length) => r.Length >= 32 + length ? r[32..(32 + length)] : null;

    /// <summary>Whether a reply is an ACK that reports success (arg0 ≥ 1), the shape most OLD commands answer with.</summary>
    private static bool IsOkAck(byte[] r) => ReplyCmd(r) == CmdAck && ReplyArg(r) >= 1;

    /// <summary>Builds a host→device OLD frame: 64-bit command, three 64-bit args, 512 data bytes (544 total, LE).</summary>
    private static byte[] OldFrame(ulong cmd, ulong arg0 = 0, ulong arg1 = 0, ulong arg2 = 0, byte[]? data = null)
    {
        var f = new byte[OldFrameSize];
        BitConverter.TryWriteBytes(f.AsSpan(0), cmd);
        BitConverter.TryWriteBytes(f.AsSpan(8), arg0);
        BitConverter.TryWriteBytes(f.AsSpan(16), arg1);
        BitConverter.TryWriteBytes(f.AsSpan(24), arg2);
        if (data is not null) Array.Copy(data, 0, f, 32, Math.Min(data.Length, 512));
        return f;
    }

    /// <summary>The longest run of printable ASCII in the bytes (the firmware banner lives in the reply's data area).</summary>
    private static string AsciiRun(byte[] b)
    {
        string best = "", cur = "";
        foreach (var x in b)
        {
            if (x is >= 0x20 and < 0x7F) { cur += (char)x; if (cur.Length > best.Length) best = cur; }
            else cur = "";
        }
        return best;
    }

    private sealed class PermissionReceiver(Action<bool> onResult) : BroadcastReceiver
    {
        public Action? Unregister;

        public override void OnReceive(Context? context, Intent? intent)
        {
            Unregister?.Invoke();
            onResult(intent?.GetBooleanExtra(UsbManager.ExtraPermissionGranted, false) ?? false);
        }
    }
}
#endif
