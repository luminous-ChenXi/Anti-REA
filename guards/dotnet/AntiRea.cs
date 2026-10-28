// AntiRea.cs — Anti-REA runtime guard (.NET / C#)
//
// Detection surface aligned with anti_rea.h: REA environment variables, analyst
// parent processes, rea-provider-*/rea-lease IPC, managed/native debuggers.
// Score-based and side-effect-free by default; the caller decides the response.
//
// Usage:
//   int score = AntiRea.Check();          // 0..100
//   string hit  = AntiRea.LastHit;
//   Recommended: check once at Program startup and again before license
//   validation; refuse activation / degrade features when score >= 60.
//
// MIT License — Anti-REA project

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace AntiRea
{
    public static class AntiRea
    {
        public const int MaxScore = 100;
        public static string LastHit { get; private set; } = "none";

        private const int WEnvRunId = 60;   // REA_PROCESS_RUN_ID: REA launched this process
        private const int WEnvBridge = 40;  // REA bridge variables
        private const int WParentTool = 40; // parent process is an analysis tool
        private const int WIpcDir = 35;     // rea-provider-* / rea-lease IPC
        private const int WDebugger = 55;   // debugger
        private const int WJobObject = 8;   // Windows Job (weak signal)

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern bool IsProcessInJob(IntPtr hProcess, IntPtr hJob, out bool result);

        private static readonly string[] ParentToolMarkers =
            { "rea.mjs", "frida", "gdb", "lldb", "ghidra", "ida", "hopper", "rizin", "mitmdump", "jadx", "apktool" };

        public static int Check()
        {
            int score = 0;
            LastHit = "none";
            void Hit(string what, int w) { score += w; LastHit = what; }

            // 1) REA environment variables (hardest signal)
            if (Environment.GetEnvironmentVariable("REA_PROCESS_RUN_ID") is { Length: > 0 })
                Hit("REA_PROCESS_RUN_ID", WEnvRunId);
            foreach (var v in new[] { "REA_SOCKET", "REA_TOKEN", "REA_RUN_ID", "REA_TARGET_PATH" })
                if (Environment.GetEnvironmentVariable(v) is { Length: > 0 })
                    Hit(v, WEnvBridge);

            // 2) Parent process chain
            try
            {
                var parent = GetParentProcess();
                for (int depth = 0; parent != null && depth < 4; depth++)
                {
                    string name = (parent.ProcessName ?? "").ToLowerInvariant();
                    if (ParentToolMarkers.Any(m => name.Contains(m)))
                    {
                        Hit("parent-tool:" + name, WParentTool);
                        break;
                    }
                    parent = GetParentProcess(parent.Id);
                }
            }
            catch { /* process may have exited */ }

            // 3) REA IPC traces
            try
            {
                string tmp = Path.GetTempPath();
                if (Directory.Exists(tmp))
                {
                    foreach (var marker in new[] { "rea-provider-", "rea-browser-scenario-" })
                        if (Directory.EnumerateDirectories(tmp, marker + "*", SearchOption.TopDirectoryOnly).Any())
                        { Hit("rea-ipc-dir", WIpcDir); break; }
                }
                if (OperatingSystem.IsWindows())
                {
                    // Named pipes: rea-lease-*
                    var pipes = Directory.EnumerateFiles(@"\\.\pipe\", "rea-lease-*");
                    if (pipes.Any()) Hit("rea-lease-pipe", WIpcDir);
                }
            }
            catch { /* ignore access-denied situations */ }

            // 4) Debuggers
            if (Debugger.IsAttached) Hit("managed-debugger", WDebugger);
            if (OperatingSystem.IsWindows())
            {
                if (IsDebuggerPresent()) Hit("native-debugger", WDebugger);
                else if (CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, out bool remote) && remote)
                    Hit("remote-debugger", WDebugger);
                if (IsProcessInJob(Process.GetCurrentProcess().Handle, IntPtr.Zero, out bool inJob) && inJob)
                    Hit("job-object", WJobObject);
            }

            // 5) Frida injection (frida/gum assembly loaded in-process)
            try
            {
                foreach (System.Reflection.Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
                {
                    string n = asm.GetName().Name ?? "";
                    if (n.IndexOf("frida", StringComparison.OrdinalIgnoreCase) >= 0) Hit("frida-assembly", 70);
                }
            }
            catch { }

            return Math.Min(score, MaxScore);
        }

        private static Process GetParentProcess(int pid = -1)
        {
            // .NET has no built-in parent-process API; use NtQueryInformationProcess (Windows only).
            if (!OperatingSystem.IsWindows()) return null;
            try
            {
                IntPtr h = pid < 0
                    ? Process.GetCurrentProcess().Handle
                    : ProcHwnd(pid);
                var pbi = new PROCESS_BASIC_INFORMATION();
                int size;
                int status = NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf(pbi), out size);
                if (status != 0 || pbi.InheritedFromUniqueProcessId == 0) return null;
                return Process.GetProcessById((int)pbi.InheritedFromUniqueProcessId);
            }
            catch { return null; }
        }

        private static IntPtr ProcHwnd(int pid)
        {
            var p = Process.GetProcessById(pid);
            return p.Handle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);
    }
}
