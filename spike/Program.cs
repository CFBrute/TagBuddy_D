using System.IO.Ports;
using TagBuddy.Services;

// Proxmark3 protocol spike. Usage:
//   dotnet run --                     -> list COM ports
//   dotnet run -- COM5 version        -> send OLD CMD_VERSION, dump reply
//   dotnet run -- COM5 read           -> send OLD CMD_HF_ISO14443A_READER (ISO14A_CONNECT), dump reply
//   dotnet run -- COM5 read 3         -> same, arg0 = 3 (CONNECT|NO_DISCONNECT)
//   dotnet run -- COM5 ng-version     -> send an NG CMD_VERSION frame instead (to confirm OLD vs NG)
//   dotnet run -- COM5 raw 50 4D ...  -> send literal bytes
//   dotnet run -- COM5 oldcmd 0x0385 1   -> send any OLD command id with arg0
//
// OLD frame: 544 bytes = uint64 cmd + uint64 arg[3] + 512 data, little-endian, no magic.
// NG frame : "PM3a" magic + (len|0x8000) + cmd16 + data + 0x3361 postamble.

const int OldFrameSize = 544;

if (args.Length == 0)
{
    Console.WriteLine("COM ports: " + string.Join(", ", SerialPort.GetPortNames().OrderBy(x => x)));
    Console.WriteLine("Usage: dotnet run -- <PORT> <version|read [arg0]|ng-version|oldcmd <id> [arg0]|raw <bytes...>>");
    return;
}

string port = args[0];
string cmd = args.Length > 1 ? args[1].ToLowerInvariant() : "version";

// old <id> <arg0> <arg1> <arg2> [data bytes...]  — fully general OLD command.
byte[] frame = cmd switch
{
    "version"    => OldFrame(0x0107),
    "read"       => OldFrame(0x0385, args.Length > 2 ? ParseU(args[2]) : 1),   // CMD_READER_ISO_14443a, arg0=flags
    "ng-version" => NgFrame(0x0107),
    "oldcmd"     => OldFrame(ParseU(args[2]), args.Length > 3 ? ParseU(args[3]) : 0),
    "old"        => OldFrameFull(args),                                        // id arg0 arg1 arg2 [data...]
    "raw"        => args.Skip(2).Select(s => (byte)ParseU(s)).ToArray(),
    _            => OldFrame(0x0107),
};

static byte[] OldFrameFull(string[] a)
{
    ulong id = ParseU(a[2]);
    ulong a0 = a.Length > 3 ? ParseU(a[3]) : 0;
    ulong a1 = a.Length > 4 ? ParseU(a[4]) : 0;
    ulong a2 = a.Length > 5 ? ParseU(a[5]) : 0;
    var data = a.Skip(6).Select(s => (byte)ParseU(s)).ToArray();
    return OldFrame(id, a0, a1, a2, data);
}

Console.WriteLine($"Opening {port} …");
using var sp = new SerialPort(port, 115200)
{
    ReadTimeout = 300,
    WriteTimeout = 1000,
    DtrEnable = true,
    RtsEnable = true,
};
sp.Open();
Thread.Sleep(150);

// Drain anything already queued (a fresh connect, or leftovers).
Drain(sp, "before");

// magicget: on ONE open, poll the HF reader until a card couples, then immediately read block 0 via the gen1a
// backdoor. Catches a brief coupling window that separate invocations would miss.
if (cmd == "magicget")
{
    byte[] readF = OldFrame(0x0385, 1);
    byte[] cgetF = OldFrame(0x0606, 0x1E, 0, 0);
    for (int i = 1; i <= 40; i++)
    {
        Drain(sp, "poll");
        sp.Write(readF, 0, readF.Length);
        var rr = ReadFor(sp, 500);
        ulong a0 = rr.Length >= 16 ? BitConverter.ToUInt64(rr, 8) : 0;
        if (a0 >= 1)
        {
            string uid = rr.Length >= 36 ? Hex(rr.AsSpan(32, 4).ToArray()) : "?";
            Console.WriteLine($"poll {i}: CARD uid={uid} -> firing backdoor read of block 0");
            Drain(sp, "pre-cget");
            sp.Write(cgetF, 0, cgetF.Length);
            var cr = ReadFor(sp, 1500);
            Console.WriteLine($"CGETBLOCK reply {cr.Length} bytes:");
            DumpOld(cr);
            return;
        }
        if (i % 5 == 0) Console.WriteLine($"poll {i}: no card yet…");
    }
    Console.WriteLine("Never coupled in 40 tries.");
    return;
}

// lfwrite <id10hex>: clone an EM410x id onto a T5577 — write the config word + the two data blocks (0x0219), then
// tell the user to re-read. Tests command id 0x0219 and the OLD arg layout (arg0=data, arg1=block, arg2=pwd).
if (cmd == "lfwrite")
{
    ulong id40 = args.Length > 2 ? ParseU("0x" + args[2].Replace("0x", "")) : 0x5C002A72ABUL;
    var (config, b1, b2) = EncodeEm410xT55xx(id40);
    Console.WriteLine($"Writing EM410x {id40 & 0xFFFFFFFFFF:X10} -> config {config:X8}, data {b1:X8} {b2:X8}");
    (uint blk, uint data)[] writes = [(1, b1), (2, b2), (0, config)];   // data blocks first, config block last
    foreach (var (blk, data) in writes)
    {
        sp.Write(OldFrame(0x0215, data, blk, 0), 0, OldFrameSize);   // CMD_T55XX_WRITE_BLOCK (0x0215, was wrongly 0x0219)
        var r = ReadFor(sp, 2000);
        Console.WriteLine($"blk {blk}: wrote {data:X8}, reply {r.Length} bytes cmd 0x{(r.Length >= 8 ? BitConverter.ToUInt64(r, 0) : 0):X}");
    }
    Console.WriteLine("Done. Run 'lfread' to confirm the id reads back.");
    return;
}

static (uint Config, uint Block1, uint Block2) EncodeEm410xT55xx(ulong id40)
{
    ulong frame = 0;
    for (int i = 0; i < 9; i++) frame = (frame << 1) | 1;
    var cols = new int[4];
    for (int row = 0; row < 10; row++)
    {
        int nibble = (int)((id40 >> ((9 - row) * 4)) & 0xF);
        int parity = 0;
        for (int bit = 3; bit >= 0; bit--)
        {
            int v = (nibble >> bit) & 1;
            parity ^= v; cols[3 - bit] ^= v;
            frame = (frame << 1) | (ulong)v;
        }
        frame = (frame << 1) | (ulong)parity;
    }
    for (int c = 0; c < 4; c++) frame = (frame << 1) | (ulong)cols[c];
    frame <<= 1;
    const uint config = 0x00148040;
    return (config, (uint)(frame >> 32), (uint)(frame & 0xFFFFFFFF));
}

// magicdump: poll until coupled, then read all 64 blocks (1K) via the backdoor, per block, reporting how many
// succeed — tests whether coupling holds for a whole dump, or whether we need a field-on sequence.
if (cmd == "magicdump")
{
    byte[] readF = OldFrame(0x0385, 1);
    bool coupled = false;
    for (int i = 0; i < 40 && !coupled; i++)
    {
        Drain(sp, "poll");
        sp.Write(readF, 0, readF.Length);
        var rr = ReadFor(sp, 500);
        coupled = (rr.Length >= 16 ? BitConverter.ToUInt64(rr, 8) : 0) >= 1;
    }
    if (!coupled) { Console.WriteLine("Never coupled."); return; }
    Console.WriteLine("coupled -> dumping 64 blocks");

    int ok = 0;
    var sw = System.Diagnostics.Stopwatch.StartNew();
    for (int b = 0; b < 64; b++)
    {
        sp.Write(OldFrame(0x0606, 0x1E, 0, (ulong)b), 0, OldFrameSize);
        var cr = ReadFor(sp, 1200);
        ulong rcmd = cr.Length >= 8 ? BitConverter.ToUInt64(cr, 0) : 0;
        ulong a0 = cr.Length >= 16 ? BitConverter.ToUInt64(cr, 8) : 0;
        if (rcmd == 0x00ff && a0 >= 1 && cr.Length >= 48)
        {
            ok++;
            Console.WriteLine($"blk {b,2}: {string.Join(" ", cr.AsSpan(32, 16).ToArray().Select(x => x.ToString("X2")))}");
        }
        else
        {
            string t = new string(cr.Where(x => x is >= 0x20 and < 0x7F).Select(x => (char)x).ToArray());
            Console.WriteLine($"blk {b,2}: FAIL ({(t.Length > 2 ? t : $"cmd 0x{rcmd:X} a0 {a0}")})");
        }
    }
    Console.WriteLine($"\n{ok}/64 blocks read in {sw.ElapsedMilliseconds} ms");
    return;
}

// magicdump2: fast dump — one unlock, field stays on across all 64 blocks. First block INIT|WUPC (0x0A, field on +
// unlock, no halt/off), middle blocks workFlags=0 (just read), last block HALT|OFF (0x14, clean up).
if (cmd == "magicdump2")
{
    byte[] readF = OldFrame(0x0385, 1);
    bool coupled = false;
    for (int i = 0; i < 40 && !coupled; i++)
    {
        Drain(sp, "poll");
        sp.Write(readF, 0, readF.Length);
        var rr = ReadFor(sp, 500);
        coupled = (rr.Length >= 16 ? BitConverter.ToUInt64(rr, 8) : 0) >= 1;
    }
    if (!coupled) { Console.WriteLine("Never coupled."); return; }
    Console.WriteLine("coupled -> fast dump");

    int ok = 0;
    var sw = System.Diagnostics.Stopwatch.StartNew();
    for (int b = 0; b < 64; b++)
    {
        ulong wf = b == 0 ? 0x0AUL : b == 63 ? 0x14UL : 0x00UL;
        sp.Write(OldFrame(0x0606, wf, 0, (ulong)b), 0, OldFrameSize);
        var cr = ReadFor(sp, 1200);
        ulong rcmd = cr.Length >= 8 ? BitConverter.ToUInt64(cr, 0) : 0;
        ulong a0 = cr.Length >= 16 ? BitConverter.ToUInt64(cr, 8) : 0;
        if (rcmd == 0x00ff && a0 >= 1 && cr.Length >= 48) { ok++; Console.WriteLine($"blk {b,2}: {string.Join(" ", cr.AsSpan(32, 16).ToArray().Select(x => x.ToString("X2")))}"); }
        else { string t = new string(cr.Where(x => x is >= 0x20 and < 0x7F).Select(x => (char)x).ToArray()); Console.WriteLine($"blk {b,2}: FAIL ({(t.Length > 2 ? t : $"cmd 0x{rcmd:X} a0 {a0}")})"); }
    }
    Console.WriteLine($"\n{ok}/64 blocks read in {sw.ElapsedMilliseconds} ms");
    return;
}

// lfread: verify the LF (125 kHz) path — acquire raw ADC samples, download them, report count + stats + a preview.
// Tests command ids 0x0205 (acquire) / 0x0207-0x0208 (download). A blank/written T5577 should return thousands of
// samples; "0 samples" or no 0x0208 frames means the ids are wrong for this firmware.
if (cmd == "lfread")
{
    Console.WriteLine("Acquiring 125 kHz samples (tag on the LF antenna)…");
    sp.Write(OldFrame(0x0205), 0, OldFrameSize);          // CMD_ACQUIRE_RAW_ADC_SAMPLES_125K
    var ack = ReadFor(sp, 3000);
    Console.WriteLine($"acquire ack: {ack.Length} bytes, cmd 0x{(ack.Length >= 8 ? BitConverter.ToUInt64(ack, 0) : 0):X}, arg0 {(ack.Length >= 16 ? BitConverter.ToUInt64(ack, 8) : 0)}");

    sp.Write(OldFrame(0x0207, 0, 20000), 0, OldFrameSize); // CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K: arg0=start, arg1=bytes
    var all = new List<byte>();
    var until = DateTime.UtcNow.AddMilliseconds(4000);
    var buf = new byte[4096];
    while (DateTime.UtcNow < until)
    {
        try { int n = sp.Read(buf, 0, buf.Length); if (n > 0) { all.AddRange(buf[..n]); until = DateTime.UtcNow.AddMilliseconds(400); } }
        catch (TimeoutException) { if (all.Count > 0) break; }
    }
    Console.WriteLine($"download: {all.Count} raw bytes received");

    // Parse 544-byte OLD frames; collect samples from CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K (0x0208).
    var samples = new List<byte>();
    int frames = 0;
    for (int off = 0; off + OldFrameSize <= all.Count; off += OldFrameSize)
    {
        ulong fcmd = BitConverter.ToUInt64(all.ToArray(), off);
        ulong a0 = BitConverter.ToUInt64(all.ToArray(), off + 8);
        ulong a1 = BitConverter.ToUInt64(all.ToArray(), off + 16);
        frames++;
        Console.WriteLine($"  frame {frames}: cmd 0x{fcmd:X}  arg0(offset) {a0}  arg1(len) {a1}");
        if (fcmd == 0x0208)
        {
            int cnt = Math.Min(Math.Min((int)a1, OldFrameSize - 32), 512);
            for (int i = 0; i < cnt; i++) samples.Add(all[off + 32 + i]);
        }
    }
    Console.WriteLine($"\n{samples.Count} samples from {frames} frames");
    if (samples.Count > 0)
    {
        int mn = 255, mx = 0; double avg = 0;
        foreach (var s in samples) { mn = Math.Min(mn, s); mx = Math.Max(mx, s); avg += s; }
        avg /= samples.Count;
        Console.WriteLine($"min {mn}  max {mx}  mean {avg:F1}");
        Console.WriteLine("first 64: " + string.Join(" ", samples.Take(64).Select(x => x.ToString("X2"))));
        // A clean middle slice (past the field/AGC settling), shown as hi/lo around the mean so the bit pattern is visible.
        var mid = samples.Skip(4000).Take(160).ToArray();
        Console.WriteLine("mid hex: " + string.Join(" ", mid.Take(64).Select(x => x.ToString("X2"))));
        Console.WriteLine("mid lvl: " + string.Concat(mid.Select(x => x >= (int)avg ? "#" : ".")));
        // A long level string so the EM410x frame (or dropouts) is visible.
        var sa = samples.ToArray();
        Console.WriteLine("levels 2000..2600:");
        Console.WriteLine(string.Concat(sa.Skip(2000).Take(600).Select(x => x >= (int)avg ? "#" : ".")));
        // run-length histogram over the whole capture (what the demod's "shortest run" would pick).
        var hist = new SortedDictionary<int, int>(); int r2 = 1;
        for (int i = 1; i < sa.Length; i++) { if ((sa[i] >= avg) == (sa[i - 1] >= avg)) r2++; else { hist[r2] = hist.GetValueOrDefault(r2) + 1; r2 = 1; } }
        Console.WriteLine("run-length histogram (len:count): " + string.Join(" ", hist.Where(kv => kv.Value >= 3).Select(kv => $"{kv.Key}:{kv.Value}")));
        var id = DemodEm410x(samples.ToArray());
        Console.WriteLine(id is ulong v ? $"\n*** EM410x id: {v:X10} ***" : "\nNo EM410x id decoded.");
    }
    return;
}

// magicset [16 hex bytes]: poll until coupled, write block 0 via the gen1a backdoor, then read it back to verify.
// With no bytes given it re-writes the CURRENT block 0 (a no-op) — the safe way to prove the write mechanism.
if (cmd == "magicset")
{
    byte[] block = args.Length >= 18
        ? args.Skip(2).Take(16).Select(s => (byte)ParseU(s)).ToArray()
        : [0x38, 0xC7, 0xE7, 0xEF, 0xF7, 0x08, 0x04, 0x00, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69];
    Console.WriteLine($"Will write block 0 = {Hex(block)}");

    byte[] readF = OldFrame(0x0385, 1);
    byte[] setF  = OldFrame(0x0605, 0, 0x1E, 0, block);   // CSETBLOCK: arg0=needWipe(0), arg1=workFlags, arg2=blockNo
    byte[] cgetF = OldFrame(0x0606, 0x1E, 0, 0);
    for (int i = 1; i <= 40; i++)
    {
        Drain(sp, "poll");
        sp.Write(readF, 0, readF.Length);
        var rr = ReadFor(sp, 500);
        if ((rr.Length >= 16 ? BitConverter.ToUInt64(rr, 8) : 0) >= 1)
        {
            Console.WriteLine($"poll {i}: coupled -> writing block 0");
            Drain(sp, "pre-set");
            sp.Write(setF, 0, setF.Length);
            var sr = ReadFor(sp, 2000);
            Console.WriteLine($"CSETBLOCK reply {sr.Length} bytes:");
            DumpOld(sr);

            Drain(sp, "pre-verify");
            sp.Write(cgetF, 0, cgetF.Length);
            var vr = ReadFor(sp, 1500);
            Console.WriteLine($"\nverify read-back {vr.Length} bytes:");
            DumpOld(vr);
            return;
        }
        if (i % 5 == 0) Console.WriteLine($"poll {i}: no card yet…");
    }
    Console.WriteLine("Never coupled in 40 tries.");
    return;
}

// ---- MIFARE Classic authenticated commands (verified against Proxmark/proxmark3 master) ----
// READBL 0x0620 / WRITEBL 0x0622: arg0=blockNo, arg1=keyType (0=A,1=B); key = data[0..5]; (write) 16 bytes = data[10..25].
// Reply is the proven symmetric 544-byte OLD layout: arg0@8 = isOK, data@32.
byte[] DefaultKey = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

byte[] ReadbData(byte[] key) { var d = new byte[512]; Array.Copy(key, 0, d, 0, 6); return d; }
byte[] WritebData(byte[] key, byte[] block16) { var d = new byte[512]; Array.Copy(key, 0, d, 0, 6); Array.Copy(block16, 0, d, 10, 16); return d; }

// The firmware prefixes replies with DEBUG_PRINT_STRING frames (e.g. "READ BLOCK FINISHED") before the real
// CMD_ACK. Read a whole window, scan every 544-byte frame, and return the CMD_ACK (0x00ff) frame specifically.
byte[]? ReadAck(int ms)
{
    var all = new List<byte>();
    var buf = new byte[1024];
    var until = DateTime.UtcNow.AddMilliseconds(ms);
    while (DateTime.UtcNow < until)
    {
        try { int n = sp.Read(buf, 0, buf.Length); if (n > 0) all.AddRange(buf[..n]); }
        catch (TimeoutException) { }
        // Peek: if we've already got a CMD_ACK frame, stop early.
        for (int off = 0; off + OldFrameSize <= all.Count; off += OldFrameSize)
            if (BitConverter.ToUInt64(all.ToArray(), off) == 0x00ff) goto done;
    }
    done:
    var bytes = all.ToArray();
    for (int off = 0; off + OldFrameSize <= bytes.Length; off += OldFrameSize)
    {
        ulong c = BitConverter.ToUInt64(bytes, off);
        if (c == 0x0100)   // debug print — surface it, it often explains a failure
        {
            ulong len = BitConverter.ToUInt64(bytes, off + 8);
            string s = new string(bytes.Skip(off + 32).Take((int)Math.Min(len, 64)).Where(x => x is >= 0x20 and < 0x7F).Select(x => (char)x).ToArray());
            Console.WriteLine($"    [fw] {s}");
        }
        if (c == 0x00ff) return bytes.AsSpan(off, OldFrameSize).ToArray();
    }
    return null;
}

// Send one OLD frame, drain first, return the ACK frame (retrying a few times to catch a coupling miss).
byte[] SendAuth(ulong id, ulong a0, ulong a1, ulong a2, byte[] data, int tries, out ulong isOk)
{
    for (int t = 0; t < tries; t++)
    {
        Drain(sp, "pre-auth");
        var f = OldFrame(id, a0, a1, a2, data);
        sp.Write(f, 0, f.Length);
        var ack = ReadAck(1500);
        if (ack is not null)
        {
            isOk = BitConverter.ToUInt64(ack, 8);
            if (isOk != 0) return ack;   // auth+op succeeded
            // isOK==0: wrong key or a coupling miss. One more try unless this was the last.
        }
    }
    isOk = 0;
    return [];
}

// mfread <blk> <A|B> [key12hex]
if (cmd == "mfread")
{
    int blk = (int)ParseU(args[2]);
    ulong kt = args.Length > 3 && args[3].Equals("B", StringComparison.OrdinalIgnoreCase) ? 1UL : 0UL;
    byte[] key = args.Length > 4 ? ParseKey(args[4]) : DefaultKey;
    var r = SendAuth(0x0620, (ulong)blk, kt, 0, ReadbData(key), 4, out ulong ok);
    Console.WriteLine($"READBL blk {blk} key{(kt == 1 ? "B" : "A")} {Hex(key)}: isOK={ok}");
    if (ok != 0 && r.Length >= 48) Console.WriteLine("  data: " + Hex(r.AsSpan(32, 16).ToArray()));
    else { Console.WriteLine("  (no data — wrong key or no coupling)"); DumpOld(r); }
    return;
}

// mfdump [A|B] [key12hex] : try to read all 64 blocks (1K) with one key
if (cmd == "mfdump")
{
    ulong kt = args.Length > 2 && args[2].Equals("B", StringComparison.OrdinalIgnoreCase) ? 1UL : 0UL;
    byte[] key = args.Length > 3 ? ParseKey(args[3]) : DefaultKey;
    Console.WriteLine($"Dumping 64 blocks with key{(kt == 1 ? "B" : "A")} {Hex(key)} …");
    int ok = 0;
    for (int b = 0; b < 64; b++)
    {
        var r = SendAuth(0x0620, (ulong)b, kt, 0, ReadbData(key), 4, out ulong isOk);
        if (isOk != 0 && r.Length >= 48) { ok++; Console.WriteLine($"blk {b,2}: {Hex(r.AsSpan(32, 16).ToArray())}"); }
        else Console.WriteLine($"blk {b,2}: ---- locked/no-read ----");
    }
    Console.WriteLine($"\n{ok}/64 blocks read.");
    return;
}

// mfwrite <blk> <A|B> <key12hex> <16 hex bytes> : authenticated write of an arbitrary block (BE CAREFUL with trailers/block0)
if (cmd == "mfwrite")
{
    int blk = (int)ParseU(args[2]);
    ulong kt = args[3].Equals("B", StringComparison.OrdinalIgnoreCase) ? 1UL : 0UL;
    byte[] key = ParseKey(args[4]);
    byte[] block16 = args.Skip(5).Take(16).Select(s => (byte)ParseU(s)).ToArray();
    if (block16.Length != 16) { Console.WriteLine($"need 16 data bytes, got {block16.Length}"); return; }
    Console.WriteLine($"WRITEBL blk {blk} key{(kt == 1 ? "B" : "A")} {Hex(key)} <- {Hex(block16)}");
    var r = SendAuth(0x0622, (ulong)blk, kt, 0, WritebData(key, block16), 4, out ulong ok);
    Console.WriteLine($"  isOK={ok}");
    DumpOld(r);
    return;
}

// mfwritekey <sector> <authA|authB> <authkey12hex> <newKeyA12hex> <newKeyB12hex>
// Writes a sector trailer, KEEPING the default access bits FF 07 80 and GPB 69 (keeps the sector fully usable/recoverable).
if (cmd == "mfwritekey")
{
    int sector = (int)ParseU(args[2]);
    int trailer = sector * 4 + 3;
    ulong kt = args[3].Equals("B", StringComparison.OrdinalIgnoreCase) ? 1UL : 0UL;
    byte[] authKey = ParseKey(args[4]);
    byte[] newA = ParseKey(args[5]);
    byte[] newB = args.Length > 6 ? ParseKey(args[6]) : DefaultKey;
    byte[] block16 = [.. newA, 0xFF, 0x07, 0x80, 0x69, .. newB];   // access bits = default transport config
    Console.WriteLine($"Sector {sector} trailer blk {trailer}: new KeyA {Hex(newA)}, access FF 07 80 69, KeyB {Hex(newB)}");
    Console.WriteLine($"  authenticating with key{(kt == 1 ? "B" : "A")} {Hex(authKey)}");
    var r = SendAuth(0x0622, (ulong)trailer, kt, 0, WritebData(authKey, block16), 5, out ulong ok);
    Console.WriteLine($"  WRITEBL isOK={ok}");
    if (ok == 0) { DumpOld(r); Console.WriteLine("  write failed — NOT verifying."); return; }

    // Verify: the first data block of the sector should now read with the NEW key A, and FAIL with the old auth key.
    int dataBlk = sector * 4;
    var rn = SendAuth(0x0620, (ulong)dataBlk, 0, 0, ReadbData(newA), 4, out ulong okNew);
    var ro = SendAuth(0x0620, (ulong)dataBlk, 0, 0, ReadbData(authKey), 3, out ulong okOld);
    Console.WriteLine($"  verify: read blk {dataBlk} with NEW keyA -> isOK={okNew} {(okNew != 0 && rn.Length >= 48 ? Hex(rn.AsSpan(32, 16).ToArray()) : "")}");
    Console.WriteLine($"  verify: read blk {dataBlk} with OLD key  -> isOK={okOld} (expect 0 if the key really changed)");
    return;
}

// mfchk <blk> <A|B> : dictionary recovery — try a list of well-known keys against one block, report which open it.
// This is the device-side recovery that finds DEFAULT/known keys. It will NOT find a truly custom key (that needs nested/darkside).
if (cmd == "mfchk")
{
    int blk = (int)ParseU(args[2]);
    ulong kt = args.Length > 3 && args[3].Equals("B", StringComparison.OrdinalIgnoreCase) ? 1UL : 0UL;
    string[] dict =
    [
        "FFFFFFFFFFFF", "000000000000", "A0A1A2A3A4A5", "D3F7D3F7D3F7", "B0B1B2B3B4B5",
        "4D3A99C351DD", "1A982C7E459A", "AABBCCDDEEFF", "112233445566", "A0B0C0D0E0F0",
    ];
    Console.WriteLine($"Dictionary check on blk {blk} key{(kt == 1 ? "B" : "A")} ({dict.Length} keys)…");
    foreach (var h in dict)
    {
        var key = ParseKey(h);
        SendAuth(0x0620, (ulong)blk, kt, 0, ReadbData(key), 3, out ulong ok);
        Console.WriteLine($"  {h}: {(ok != 0 ? "*** OPENS ***" : "no")}");
    }
    return;
}

// nested <targetSector=1> [knownKeyHex=FFFFFFFFFFFF] [rounds=5] [expectKeyHex]
// Collects encrypted nonces for the target sector (NESTED 0x0612) using a known key on sector 0, then runs the
// Crypto1 solver. If expectKeyHex is given (the key you wrote to the target with mfwritekey — recorded ONLY for
// this check), it forward-verifies which byte order of the firmware's nt/ks reproduces that key: that pins down
// the device->solver mapping the TODO calls out, without ever feeding the key into the recovery itself.
if (cmd == "nested")
{
    int tSector = args.Length > 2 ? (int)ParseU(args[2]) : 1;
    byte[] known = args.Length > 3 ? ParseKey(args[3]) : DefaultKey;
    int rounds = args.Length > 4 ? (int)ParseU(args[4]) : 5;
    byte[]? expect = args.Length > 5 ? ParseKey(args[5]) : null;
    int knownBlock = 0, targetBlock = tSector * 4;

    static ulong KeyToU64(byte[] k) => ((ulong)k[0] << 40) | ((ulong)k[1] << 32) | ((ulong)k[2] << 24) | ((ulong)k[3] << 16) | ((ulong)k[4] << 8) | k[5];
    static uint Bswap(uint x) => (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
    static uint Ksw(ulong key, uint input) { var s = Crypto1State.FromKey(key); return Crypto1.Word(s, input, false); }

    Console.WriteLine($"Nested: known = block {knownBlock} keyA {Hex(known)}, target = sector {tSector} (block {targetBlock}) keyA.");
    if (expect is not null) Console.WriteLine($"  (diagnostic) expecting target key {Hex(expect)} — will report which nt/ks byte order reproduces it.");

    List<ulong>? inter = null;
    bool mappingShown = false;
    for (int round = 0; round < rounds && (inter is null || inter.Count > 1); round++)
    {
        Drain(sp, "pre-nested");
        var f = OldFrame(0x0612, (ulong)knownBlock, (ulong)targetBlock, round == 0 ? 1UL : 0UL, ReadbData(known));
        sp.Write(f, 0, f.Length);
        var ack = ReadAck(4000);
        if (ack is null) { Console.WriteLine($"round {round}: no ACK (known key may not open sector 0, or the card moved)."); continue; }
        var d = ack.AsSpan(32, 28).ToArray();
        uint U(int o) => (uint)(d[o] | d[o + 1] << 8 | d[o + 2] << 16 | d[o + 3] << 24);
        uint cuid = U(0), nt0 = U(4), ks0 = U(8), nt1 = U(12), ks1 = U(16), tmo = U(20), fnt = U(24);
        Console.WriteLine($"round {round}: raw {Hex(d)}");
        Console.WriteLine($"  cuid {cuid:X8}  nt0 {nt0:X8} ks0 {ks0:X8}  nt1 {nt1:X8} ks1 {ks1:X8}  timeout {tmo} fixed_nt {fnt:X8}");

        var pairs = new[] { (nt0, ks0), (nt1, ks1) };

        // Diagnostic: find the (uid, nt, ks) byte order that forward-reproduces the known key.
        if (expect is not null && !mappingShown)
        {
            ulong K = KeyToU64(expect);
            (string, uint)[] inputs(uint nt) =>
            [
                ("uid^nt", cuid ^ nt), ("bswap(uid)^nt", Bswap(cuid) ^ nt), ("uid^bswap(nt)", cuid ^ Bswap(nt)),
                ("bswap(uid^nt)", Bswap(cuid ^ nt)), ("bswap(uid)^bswap(nt)", Bswap(cuid) ^ Bswap(nt)),
                ("nt", nt), ("bswap(nt)", Bswap(nt)),
            ];
            foreach (var (nt, ks) in pairs)
            {
                foreach (var (iLbl, iVal) in inputs(nt))
                    foreach (var (kLbl, kVal) in new[] { ("ks", ks), ("bswap(ks)", Bswap(ks)) })
                        if (Ksw(K, iVal) == kVal)
                        {
                            Console.WriteLine($"  >>> MAPPING: input={iLbl}, keystream={kLbl} reproduces the known key. <<<");
                            mappingShown = true;
                        }
            }
            if (!mappingShown) Console.WriteLine("  (diagnostic) no simple byte-order combo reproduced the key — nt may be the PRNG-predicted nonce or ks defined differently; dump above is the clue.");
        }

        // Recovery with the as-coded mapping (uid=cuid, input=uid^nt, keystream=ks).
        foreach (var (nt, ks) in pairs)
        {
            var set = Crypto1.Nonce2Key(cuid, nt, ks);
            string has = expect is not null ? (set.Contains(KeyToU64(expect)) ? "  [contains expected key]" : "  [expected key NOT in set]") : "";
            Console.WriteLine($"    nonce nt {nt:X8}: {set.Count} candidates{has}");
            inter = inter is null ? set : Crypto1.Intersect(inter, set);
        }
        Console.WriteLine($"  intersection so far: {inter?.Count ?? 0}");
    }

    if (inter is null || inter.Count == 0) { Console.WriteLine("No key recovered. If the dump looks sane, the mapping line above tells you what to change."); return; }
    Console.WriteLine($"{inter.Count} candidate(s) survived; proving on the card by reading block {targetBlock}…");
    foreach (var cand in inter.Take(16))
    {
        var key = new byte[6];
        for (int i = 0; i < 6; i++) key[i] = (byte)(cand >> (40 - 8 * i));
        var r = SendAuth(0x0620, (ulong)targetBlock, 0, 0, ReadbData(key), 3, out ulong ok);
        if (ok != 0) { Console.WriteLine($"  *** RECOVERED key A for sector {tSector}: {Hex(key)} *** (block {targetBlock}: {(r.Length >= 48 ? Hex(r.AsSpan(32, 16).ToArray()) : "")})"); return; }
    }
    Console.WriteLine("  none of the surviving candidates opened the sector — see the diagnostic above.");
    return;
}

static byte[] ParseKey(string hex)
{
    hex = hex.Replace(" ", "").Replace("0x", "");
    if (hex.Length != 12) throw new ArgumentException($"key must be 12 hex chars, got '{hex}'");
    var b = new byte[6];
    for (int i = 0; i < 6; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    return b;
}

Console.WriteLine($"TX ({frame.Length} bytes): {Hex(frame.AsSpan(0, Math.Min(frame.Length, 16)).ToArray())}{(frame.Length > 16 ? " …" : "")}");
sp.Write(frame, 0, frame.Length);

// Read everything the device sends back for ~2.5 s.
var rx = ReadFor(sp, 2500);
Console.WriteLine($"\nRX {rx.Length} bytes:");
DumpOld(rx);

static void Drain(SerialPort sp, string when)
{
    var buf = new byte[1024];
    int total = 0;
    var until = DateTime.UtcNow.AddMilliseconds(400);
    while (DateTime.UtcNow < until)
    {
        try { int n = sp.Read(buf, 0, buf.Length); total += n; until = DateTime.UtcNow.AddMilliseconds(200); }
        catch (TimeoutException) { break; }
    }
    if (total > 0) Console.WriteLine($"(drained {total} stale bytes {when} the command)");
}

static byte[] ReadFor(SerialPort sp, int ms)
{
    var all = new List<byte>();
    var buf = new byte[1024];
    var until = DateTime.UtcNow.AddMilliseconds(ms);
    while (DateTime.UtcNow < until)
    {
        try { int n = sp.Read(buf, 0, buf.Length); if (n > 0) all.AddRange(buf[..n]); }
        catch (TimeoutException) { if (all.Count > 0) break; }   // data then a gap = reply complete
    }
    return all.ToArray();
}

static void DumpOld(byte[] b)
{
    if (b.Length == 0) { Console.WriteLine("(nothing)"); return; }
    if (b.Length >= 8)
    {
        ulong c = BitConverter.ToUInt64(b, 0);
        Console.WriteLine($"  OLD cmd = 0x{c:X}");
        if (b.Length >= 32)
            Console.WriteLine($"  arg0 = 0x{BitConverter.ToUInt64(b, 8):X}  arg1 = 0x{BitConverter.ToUInt64(b, 16):X}  arg2 = 0x{BitConverter.ToUInt64(b, 24):X}");
    }
    // hex + ascii, 16 per line
    for (int i = 0; i < b.Length; i += 16)
    {
        var line = b.AsSpan(i, Math.Min(16, b.Length - i)).ToArray();
        string hex = string.Join(" ", line.Select(x => x.ToString("X2"))).PadRight(16 * 3);
        string asc = new string(line.Select(x => x is >= 0x20 and < 0x7F ? (char)x : '.').ToArray());
        Console.WriteLine($"  {i:D4}: {hex} {asc}");
    }
}

static byte[] OldFrame(ulong cmd, ulong arg0 = 0, ulong arg1 = 0, ulong arg2 = 0, byte[]? data = null)
{
    var f = new byte[OldFrameSize];
    BitConverter.TryWriteBytes(f.AsSpan(0), cmd);
    BitConverter.TryWriteBytes(f.AsSpan(8), arg0);
    BitConverter.TryWriteBytes(f.AsSpan(16), arg1);
    BitConverter.TryWriteBytes(f.AsSpan(24), arg2);
    if (data is { Length: > 0 }) Array.Copy(data, 0, f, 32, Math.Min(data.Length, 512));
    return f;
}

static byte[] NgFrame(ushort cmd, byte[]? data = null)
{
    data ??= [];
    ushort lenWord = (ushort)((data.Length & 0x7FFF) | 0x8000);
    var f = new byte[8 + data.Length + 2];
    f[0] = 0x50; f[1] = 0x4D; f[2] = 0x33; f[3] = 0x61;
    f[4] = (byte)(lenWord & 0xFF); f[5] = (byte)(lenWord >> 8);
    f[6] = (byte)(cmd & 0xFF); f[7] = (byte)(cmd >> 8);
    data.CopyTo(f, 8);
    int crc = 8 + data.Length;
    f[crc] = 0x61; f[crc + 1] = 0x33;
    return f;
}

// --- EM410x demod, copied verbatim from the app (ProxmarkUsb.cs) to verify it on a real capture ---
static ulong? DemodEm410x(byte[] raw)
{
    // Skip the field/AGC settling at the start.
    int skip = Math.Min(200, raw.Length / 10);
    int n = raw.Length - skip;
    if (n < 256) return null;
    var samples = new byte[n];
    Array.Copy(raw, skip, samples, 0, n);

    double mean = 0; for (int i = 0; i < n; i++) mean += samples[i]; mean /= n;
    var hi = new bool[n];
    for (int i = 0; i < n; i++) hi[i] = samples[i] >= mean;

    // Runs of constant level: (level, length).
    var runLevel = new List<bool>(); var runLen = new List<int>();
    int run = 1;
    for (int i = 1; i < n; i++) { if (hi[i] == hi[i - 1]) run++; else { runLevel.Add(hi[i - 1]); runLen.Add(run); run = 1; } }
    runLevel.Add(hi[n - 1]); runLen.Add(run);
    if (runLen.Count < 20) return null;

    // Half-bit length from the dominant *short* run cluster (robust to noise, unlike the absolute shortest run).
    var hist = new Dictionary<int, int>();
    foreach (var r in runLen) if (r >= 3) hist[r] = hist.GetValueOrDefault(r) + 1;
    if (hist.Count == 0) return null;
    int maxCount = hist.Values.Max();
    int minCommon = hist.Where(kv => kv.Value >= maxCount / 4).Select(kv => kv.Key).DefaultIfEmpty(0).Min();
    if (minCommon < 3) return null;
    double num = 0, den = 0;
    foreach (var kv in hist) if (kv.Value >= maxCount / 4 && kv.Key < minCommon * 1.5) { num += (double)kv.Key * kv.Value; den += kv.Value; }
    if (den == 0) return null;
    double half = num / den;
    if (half < 3) return null;

    // Convert each run to whole half-bits (run≈half → 1, run≈2·half → 2): robust to timing jitter, no drift.
    var bits = new List<bool>();
    for (int i = 0; i < runLen.Count; i++)
    {
        int c = Math.Max(1, (int)Math.Round(runLen[i] / half));
        for (int k = 0; k < c; k++) bits.Add(runLevel[i]);
    }

    Console.WriteLine($"[demod] half={half:F2}  halfbits={bits.Count}");
    Console.WriteLine("[demod] halfbit levels: " + string.Concat(bits.Take(160).Select(x => x ? "1" : "0")));

    for (int phase = 0; phase < 2; phase++)
    {
        var decoded = new List<int>(bits.Count / 2);
        bool ok = true;
        for (int i = phase; i + 1 < bits.Count; i += 2)
        {
            if (!bits[i] && bits[i + 1]) decoded.Add(0);
            else if (bits[i] && !bits[i + 1]) decoded.Add(1);
            else { ok = false; break; }
        }
        if (ok && Em410xFromBits(decoded) is { } id) return id;
    }
    return null;
}

static ulong? Em410xFromBits(List<int> b)
{
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
            if (b[p++] != parity) good = false;
        }
        if (!good) continue;
        bool colsOk = true;
        for (int c = 0; c < 4; c++) if (b[p++] != cols[c]) { colsOk = false; break; }
        if (colsOk && b[p] == 0) return id;
    }
    return null;
}

static ulong ParseU(string s) =>
    s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
        ? Convert.ToUInt64(s[2..], 16)
        : Convert.ToUInt64(s, 10);

static string Hex(byte[] b) => string.Join(" ", b.Select(x => x.ToString("X2")));
