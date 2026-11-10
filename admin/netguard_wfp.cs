// NetGuard: system-wide kill switch on the Windows Filtering Platform.
// Design follows wireguard-windows tunnel/firewall: one max-weight persistent sublayer,
// soft permits for the TUN address / proxy core / local traffic, then block everything else.
// Struct layouts are the same ones ClaudeGuard's windows_wfp.cs already uses on this machine.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public sealed class NetGuardWfp : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct Display { public IntPtr name, description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Sequential)] struct Value { public uint type; public ulong value; }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid field; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid key; }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob data; public Guid layer, sublayer; public Value weight;
        public uint count; public IntPtr conditions; public Action action;
        public ulong context, contextPadding; public IntPtr reserved; public ulong id; public Value effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Sublayer {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob data; public ushort weight;
    }
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr handle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr handle, uint requested, out IntPtr entries, out uint returned);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr handle);
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file, out IntPtr blob);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);

    // Layers: FWPM_LAYER_ALE_AUTH_CONNECT_V4 / _V6
    static readonly Guid ConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    static readonly Guid ConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    // Condition fields
    static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static readonly Guid LocalAddress = new Guid("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957");
    static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
    static readonly Guid Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
    const uint MatchEqual = 0, MatchFlagsAllSet = 6;
    const uint TypeUint16 = 2, TypeUint32 = 3, TypeBlob = 12, TypeV4Mask = 0x100, TypeV6Mask = 0x101;
    const uint Block = 0x1001, Permit = 0x1002;
    const uint Persistent = 1;

    public static readonly Guid SublayerKey = Key("NetGuard/sublayer/v1");
    IntPtr engine;
    readonly List<IntPtr> allocations = new List<IntPtr>();
    readonly List<IntPtr> wfpAllocations = new List<IntPtr>();

    static void Check(uint result, string what) { if (result != 0) throw new InvalidOperationException(what + " 失败：WFP 0x" + result.ToString("X8")); }
    static Guid Key(string text) { using (var h = SHA256.Create()) { var b = h.ComputeHash(Encoding.UTF8.GetBytes(text)); var k = new byte[16]; Array.Copy(b, k, 16); return new Guid(k); } }

    public NetGuardWfp() {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("需要 64 位 PowerShell");
        if (Marshal.SizeOf(typeof(Filter)) != 200 || Marshal.SizeOf(typeof(Condition)) != 40) throw new InvalidOperationException("WFP 结构体布局不符");
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine), "打开 WFP 引擎");
    }

    // Keys and display names of our filters currently in the engine.
    public List<string> Current() {
        var names = new List<string>();
        foreach (var f in Enumerate()) names.Add(f.Value);
        return names;
    }

    // Read-only inspector: retain the ALE layer so v4 duplicates cannot mask missing v6 rules.
    public List<string> CurrentByLayer() {
        var result = new List<string>();
        IntPtr handle;
        Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out handle), "枚举过滤器层级");
        try {
            while (true) {
                IntPtr entries; uint count;
                Check(FwpmFilterEnum0(engine, handle, 512, out entries, out count), "枚举过滤器层级");
                try {
                    for (int i = 0; i < count; i++) {
                        IntPtr item = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        Filter f = (Filter)Marshal.PtrToStructure(item, typeof(Filter));
                        if (f.sublayer != SublayerKey) continue;
                        string layer = f.layer == ConnectV4 ? "v4" : f.layer == ConnectV6 ? "v6" : "unknown";
                        string name = f.display.name == IntPtr.Zero ? "" : Marshal.PtrToStringUni(f.display.name);
                        result.Add(layer + "|" + name);
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                if (count < 512) break;
            }
        } finally { FwpmFilterDestroyEnumHandle0(engine, handle); }
        return result;
    }

    // Read-only: filters owned by someone else whose display name OR description contains any of
    // the given lowercase fragments. Used to prove the FlClash/mihomo (sing-tun) strict-route
    // filters are really installed at runtime. sing-tun (MetaCubeX/sing-tun, tun_windows.go) uses
    // CreateDisplayData("sing-tun", "block ipv4 dns"): the NAME is "sing-tun" and the rule text is
    // the DESCRIPTION, inside a dynamic session that exists only while strict-route is active.
    // Returns "layerGuid|action|name|description".
    public List<string> ExternalMatching(string[] fragments) {
        var result = new List<string>();
        IntPtr handle;
        Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out handle), "枚举外部过滤器");
        try {
            while (true) {
                IntPtr entries; uint count;
                Check(FwpmFilterEnum0(engine, handle, 512, out entries, out count), "枚举外部过滤器");
                try {
                    for (int i = 0; i < count; i++) {
                        IntPtr item = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        Filter f = (Filter)Marshal.PtrToStructure(item, typeof(Filter));
                        if (f.sublayer == SublayerKey) continue;
                        string name = Marshal.PtrToStringUni(f.display.name) ?? "";
                        string desc = f.display.description == IntPtr.Zero ? "" : (Marshal.PtrToStringUni(f.display.description) ?? "");
                        string lower = (name + " " + desc).ToLowerInvariant();
                        foreach (string frag in fragments) {
                            if (lower.Contains(frag)) {
                                string action = f.action.type == Block ? "block" : f.action.type == Permit ? "permit" : "0x" + f.action.type.ToString("X");
                                result.Add(f.layer + "|" + action + "|" + name.Replace("|", "/") + "|" + desc.Replace("|", "/"));
                                break;
                            }
                        }
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                if (count < 512) break;
            }
        } finally { FwpmFilterDestroyEnumHandle0(engine, handle); }
        return result;
    }

    List<KeyValuePair<Guid, string>> Enumerate() {
        var result = new List<KeyValuePair<Guid, string>>();
        IntPtr handle;
        Check(FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out handle), "枚举过滤器");
        try {
            while (true) {
                IntPtr entries; uint count;
                Check(FwpmFilterEnum0(engine, handle, 512, out entries, out count), "枚举过滤器");
                try {
                    for (int i = 0; i < count; i++) {
                        IntPtr item = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        Filter f = (Filter)Marshal.PtrToStructure(item, typeof(Filter));
                        if (f.sublayer == SublayerKey)
                            result.Add(new KeyValuePair<Guid, string>(f.key, f.display.name == IntPtr.Zero ? "" : Marshal.PtrToStringUni(f.display.name)));
                    }
                } finally { if (entries != IntPtr.Zero) FwpmFreeMemory0(ref entries); }
                if (count < 512) break;
            }
        } finally { FwpmFilterDestroyEnumHandle0(engine, handle); }
        return result;
    }

    // Replace all NetGuard filters atomically.
    //   killswitch: block everything except TUN / proxy apps / local traffic
    //   blockApps:  hard-block these programs (used for real-IP mode)
    public void Apply(bool killswitch, string tunV4, int tunV4Prefix, string tunV6, int tunV6Prefix, string[] allowApps, string[] blockApps) {
        allowApps = allowApps ?? new string[0];
        blockApps = blockApps ?? new string[0];
        Check(FwpmTransactionBegin0(engine, 0), "开始事务");
        try {
            foreach (var f in Enumerate()) { Guid k = f.Key; Check(FwpmFilterDeleteByKey0(engine, ref k), "删除旧规则"); }
            if (killswitch || blockApps.Length > 0) EnsureSublayer();
            foreach (Guid layer in new[] { ConnectV4, ConnectV6 }) {
                bool v4 = layer == ConnectV4;
                string tag = v4 ? "v4" : "v6";
                foreach (string app in blockApps) Add(layer, "real-ip block " + app, 15, Block, CondApp(app));
                if (!killswitch) continue;
                Add(layer, "permit TUN " + tag, 14, Permit, v4 ? CondV4(LocalAddress, tunV4, tunV4Prefix) : CondV6(LocalAddress, tunV6, tunV6Prefix));
                foreach (string app in allowApps) Add(layer, "permit proxy app " + app, 14, Permit, CondApp(app));
                Add(layer, "block DNS outside TUN " + tag, 13, Block, Cond(RemotePort, MatchEqual, TypeUint16, 53));
                Add(layer, "permit loopback " + tag, 12, Permit, Cond(Flags, MatchFlagsAllSet, TypeUint32, 1));
                var local = new List<Condition>();
                if (v4) {
                    foreach (var net in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32" }) {
                        var p = net.Split('/'); local.Add(CondV4(RemoteAddress, p[0], int.Parse(p[1])));
                    }
                } else {
                    foreach (var net in new[] { "fe80::/10", "ff00::/8", "fc00::/7" }) {
                        var p = net.Split('/'); local.Add(CondV6(RemoteAddress, p[0], int.Parse(p[1])));
                    }
                }
                Add(layer, "permit LAN/link-local " + tag, 12, Permit, local.ToArray());
                Add(layer, "block all other " + tag, 0, Block);
            }
            Check(FwpmTransactionCommit0(engine), "提交事务");
        } catch { FwpmTransactionAbort0(engine); throw; }
        finally { FreeAll(); }
        if (!killswitch && blockApps.Length == 0) { Guid s = SublayerKey; FwpmSubLayerDeleteByKey0(engine, ref s); }
    }

    // Strengthen an existing isolation without touching ANY existing rule.
    // The caller checks the base killswitch before and after this transaction.
    public int EnsureBlockedApps(string[] apps) {
        if (apps == null || apps.Length == 0) throw new ArgumentException("隔离清单不能为空");
        Check(FwpmTransactionBegin0(engine, 0), "开始隔离补充事务");
        try {
            var present = new HashSet<Guid>();
            foreach (var item in Enumerate()) present.Add(item.Key);
            int added = 0;
            foreach (Guid layer in new[] { ConnectV4, ConnectV6 }) {
                foreach (string app in apps) {
                    if (String.IsNullOrWhiteSpace(app)) throw new ArgumentException("隔离路径不能为空");
                    string name = "real-ip block " + app;
                    Guid key = Key("NetGuard/filter/" + layer + "/" + name);
                    if (present.Contains(key)) continue;
                    Add(layer, name, 15, Block, CondApp(app));
                    present.Add(key);
                    added++;
                }
            }
            Check(FwpmTransactionCommit0(engine), "提交隔离补充事务");
            return added;
        } catch { FwpmTransactionAbort0(engine); throw; }
        finally { FreeAll(); }
    }

    void EnsureSublayer() {
        IntPtr title = Marshal.StringToHGlobalUni("NetGuard kill switch");
        try {
            Sublayer sub = new Sublayer { key = SublayerKey, display = new Display { name = title }, flags = Persistent, weight = 0xFFFF };
            uint r = FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero);
            if (r != 0x80320009) Check(r, "创建子层"); // FWP_E_ALREADY_EXISTS
        } finally { Marshal.FreeHGlobal(title); }
    }

    void Add(Guid layer, string name, int weight, uint action, params Condition[] conditions) {
        IntPtr conds = IntPtr.Zero;
        if (conditions.Length > 0) {
            int size = Marshal.SizeOf(typeof(Condition));
            conds = Alloc(size * conditions.Length);
            for (int i = 0; i < conditions.Length; i++) Marshal.StructureToPtr(conditions[i], conds + i * size, false);
        }
        IntPtr title = Marshal.StringToHGlobalUni("NetGuard " + name);
        allocations.Add(title);
        Filter f = new Filter {
            key = Key("NetGuard/filter/" + layer + "/" + name), display = new Display { name = title }, flags = Persistent,
            layer = layer, sublayer = SublayerKey, weight = new Value { type = 1, value = (ulong)weight },
            count = (uint)conditions.Length, conditions = conds, action = new Action { type = action }
        };
        ulong id; Check(FwpmFilterAdd0(engine, ref f, IntPtr.Zero, out id), "添加规则 " + name);
    }

    Condition Cond(Guid field, uint match, uint type, ulong value) {
        return new Condition { field = field, match = match, value = new Value { type = type, value = value } };
    }
    Condition CondApp(string path) {
        IntPtr blob;
        Check(FwpmGetAppIdFromFileName0(path, out blob), "解析程序 " + path);
        wfpAllocations.Add(blob);
        return Cond(AppId, MatchEqual, TypeBlob, unchecked((ulong)blob.ToInt64()));
    }
    Condition CondV4(Guid field, string address, int prefix) {
        byte[] b = System.Net.IPAddress.Parse(address).GetAddressBytes();
        uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        IntPtr p = Alloc(8);
        Marshal.WriteInt32(p, 0, unchecked((int)(addr & mask)));
        Marshal.WriteInt32(p, 4, unchecked((int)mask));
        return Cond(field, MatchEqual, TypeV4Mask, unchecked((ulong)p.ToInt64()));
    }
    Condition CondV6(Guid field, string address, int prefix) {
        byte[] b = System.Net.IPAddress.Parse(address).GetAddressBytes();
        IntPtr p = Alloc(17);
        Marshal.Copy(b, 0, p, 16);
        Marshal.WriteByte(p, 16, (byte)prefix);
        return Cond(field, MatchEqual, TypeV6Mask, unchecked((ulong)p.ToInt64()));
    }
    IntPtr Alloc(int size) { IntPtr p = Marshal.AllocHGlobal(size); allocations.Add(p); return p; }
    void FreeAll() {
        foreach (var p in allocations) Marshal.FreeHGlobal(p);
        allocations.Clear();
        for (int i = 0; i < wfpAllocations.Count; i++) { IntPtr p = wfpAllocations[i]; FwpmFreeMemory0(ref p); }
        wfpAllocations.Clear();
    }
    public void Dispose() { FreeAll(); if (engine != IntPtr.Zero) { FwpmEngineClose0(engine); engine = IntPtr.Zero; } }
}
