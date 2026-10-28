/*
 * anti_rea.h — Anti-REA runtime guard (C/C++ single header, cross-platform)
 *
 * Detects runtime footprints of REA (Reverse Engineer Anything) and similar
 * reverse-engineering pipelines:
 *   - REA_PROCESS_RUN_ID environment variable injected by REA's process capture (hardest signal)
 *   - REA bridge-process environment (REA_SOCKET / REA_TOKEN / REA_RUN_ID / REA_TARGET_PATH)
 *   - REA temp IPC locations (unix: $TMPDIR/rea-provider-*; win: \\.\pipe\rea-lease-*)
 *   - Known analysis tools in the parent process chain: rea.mjs / frida / gdb / lldb /
 *     ghidra / ida / hopper / rizin / mitmdump
 *   - Frida injection traces (gum-js-loop thread name, frida-agent module/mappings)
 *   - Conventional anti-debugging (ptrace self-check / IsDebuggerPresent / remote debugger)
 *   - Windows Job Object membership (REA puts managed children in a Job; weak signal —
 *     plenty of legitimate software uses Job objects too)
 *
 * Design principles: score-based, side-effect-free by default — this header never
 * crashes or exits on its own. The caller decides the response from the score
 * (log / degrade / exit / silently feed bogus results).
 *
 * Usage:
 *   #define ANTI_REA_IMPLEMENTATION  // in exactly one translation unit
 *   #include "anti_rea.h"
 *   int score = anti_rea_score();    // 0..100
 *   if (score >= 60) { ... }
 *
 * MIT License — Anti-REA project
 */
#ifndef ANTI_REA_H
#define ANTI_REA_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define ANTI_REA_MAX_SCORE 100

/* Vector weights: hard signals weigh heavily, environmental weak signals lightly
 * to avoid penalizing real users */
#define ANTI_REA_W_ENV_RUN_ID   60  /* REA_PROCESS_RUN_ID — REA launched this process */
#define ANTI_REA_W_ENV_BRIDGE   40  /* REA bridge vars — this process is an analysis bridge */
#define ANTI_REA_W_PARENT_TOOL  40  /* parent process is a known analysis tool */
#define ANTI_REA_W_IPC_DIR      35  /* rea-provider-*/rea-lease IPC found */
#define ANTI_REA_W_FRIDA        70  /* Frida injection */
#define ANTI_REA_W_DEBUGGER     55  /* debugger attached */
#define ANTI_REA_W_JOB_OBJECT   8   /* Windows Job (weak signal) */

#ifdef __cplusplus
extern "C" {
#endif

int anti_rea_score(void);
const char *anti_rea_last_hit(void);

#ifdef __cplusplus
}
#endif

#endif /* ANTI_REA_H */

#ifdef ANTI_REA_IMPLEMENTATION

static char g_last_hit[128] = "none";

static void anti_rea_hit(const char *what, int *score, int weight) {
    *score += weight;
    snprintf(g_last_hit, sizeof(g_last_hit), "%s", what);
}

/* ---------------- Environment variable scan (cross-platform) ---------------- */
static int anti_rea_scan_env(int *score) {
    static const char *runId[] = {"REA_PROCESS_RUN_ID", NULL};
    static const char *bridge[] = {"REA_SOCKET", "REA_TOKEN", "REA_RUN_ID", "REA_TARGET_PATH", NULL};
    for (int i = 0; runId[i]; i++)
        if (getenv(runId[i])) { anti_rea_hit(runId[i], score, ANTI_REA_W_ENV_RUN_ID); return 1; }
    for (int i = 0; bridge[i]; i++)
        if (getenv(bridge[i])) anti_rea_hit(bridge[i], score, ANTI_REA_W_ENV_BRIDGE);
    return 0;
}

/* ---------------- Parent process command-line scan ---------------- */
#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
static int anti_rea_scan_parent(int *score) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    DWORD ppid = 0, self = GetCurrentProcessId();
    if (Process32FirstW(snap, &pe)) {
        do { if (pe.th32ProcessID == self) { ppid = pe.th32ParentProcessID; break; } } while (Process32NextW(snap, &pe));
    }
    if (ppid) {
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == ppid) {
                    char name[64]; WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), NULL, NULL);
                    for (char *p = name; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
                    if (strstr(name, "rea.mjs") || strstr(name, "frida") || strstr(name, "gdb") ||
                        strstr(name, "lldb") || strstr(name, "ghidra") || strstr(name, "ida") ||
                        strstr(name, "hopper") || strstr(name, "rizin") || strstr(name, "mitmdump"))
                        anti_rea_hit("parent-tool", score, ANTI_REA_W_PARENT_TOOL);
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
    }
    CloseHandle(snap);
    return 0;
}
#else /* POSIX: read /proc/<ppid>/cmdline */
#include <unistd.h>
static int anti_rea_scan_parent(int *score) {
    char path[64], buf[4096];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)getppid());
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    for (size_t i = 0; i < n; i++) if (buf[i] == 0) buf[i] = ' ';
    for (char *p = buf; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
    if (strstr(buf, "rea.mjs") || strstr(buf, "frida") || strstr(buf, "gdb") ||
        strstr(buf, "lldb") || strstr(buf, "ghidra") || strstr(buf, "ida") ||
        strstr(buf, "hopper") || strstr(buf, "rizin") || strstr(buf, "mitmdump"))
        anti_rea_hit("parent-tool", score, ANTI_REA_W_PARENT_TOOL);
    return 0;
}
#endif

/* ---------------- REA IPC / Frida / anti-debugging (per platform) ---------------- */
#if defined(_WIN32)

static int anti_rea_scan_win(int *score) {
    /* REA lease named pipes: \\.\pipe\rea-lease-* */
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strncmp(fd.cFileName, "rea-lease-", 10) == 0) {
                anti_rea_hit("rea-lease-pipe", score, ANTI_REA_W_IPC_DIR);
                break;
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    /* Job Object membership (weak signal) */
    BOOL inJob = FALSE;
    if (IsProcessInJob(GetCurrentProcess(), NULL, &inJob) && inJob)
        anti_rea_hit("job-object", score, ANTI_REA_W_JOB_OBJECT);
    /* Anti-debugging */
    if (IsDebuggerPresent()) anti_rea_hit("is-debugger-present", score, ANTI_REA_W_DEBUGGER);
    else {
        BOOL remote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
            anti_rea_hit("remote-debugger", score, ANTI_REA_W_DEBUGGER);
    }
    /* Frida module scan */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me; me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                char name[128]; WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, name, sizeof(name), NULL, NULL);
                for (char *p = name; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
                if (strstr(name, "frida") || strstr(name, "gum"))
                    anti_rea_hit("frida-module", score, ANTI_REA_W_FRIDA);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    return 0;
}

#else /* POSIX */

#include <dirent.h>
#include <sys/ptrace.h>
#if defined(__APPLE__)
#define ANTI_REA_PTRACE_TRACEME PT_TRACE_ME
#else
#define ANTI_REA_PTRACE_TRACEME PTRACE_TRACEME
#endif

static int anti_rea_scan_posix(int *score) {
    /* rea-provider-* under TMPDIR (REA socket/lease directories) */
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) tmp = "/tmp";
    DIR *d = opendir(tmp);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strncmp(e->d_name, "rea-provider-", 13) == 0 || strncmp(e->d_name, "rea-browser-scenario-", 22) == 0) {
                anti_rea_hit("rea-ipc-dir", score, ANTI_REA_W_IPC_DIR);
                break;
            }
        }
        closedir(d);
    }
    /* Frida: gum thread names / frida mappings */
    DIR *tasks = opendir("/proc/self/task");
    if (tasks) {
        struct dirent *t;
        char p[96], comm[64];
        while ((t = readdir(tasks))) {
            if (t->d_name[0] < '0' || t->d_name[0] > '9') continue;
            snprintf(p, sizeof(p), "/proc/self/task/%s/comm", t->d_name);
            FILE *f = fopen(p, "r");
            if (!f) continue;
            if (fgets(comm, sizeof(comm), f)) {
                if (strstr(comm, "gum-js-loop") || strstr(comm, "gmain") || strstr(comm, "frida"))
                    anti_rea_hit("frida-thread", score, ANTI_REA_W_FRIDA);
            }
            fclose(f);
        }
        closedir(tasks);
    }
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            for (char *p = line; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
            if (strstr(line, "frida") || strstr(line, "gum-js")) { anti_rea_hit("frida-mapping", score, ANTI_REA_W_FRIDA); break; }
        }
        fclose(maps);
    }
    /* Anti-debugging: ptrace self-check. TRACEME fails (EPERM) when a debugger is
     * already attached. On success it merely marks the parent as tracer — no other
     * side effect; no ptrace call afterwards. */
    errno = 0;
    if (ptrace(ANTI_REA_PTRACE_TRACEME, 0, 0, 0) != 0) {
        anti_rea_hit("ptrace-traced", score, ANTI_REA_W_DEBUGGER);
    }
    return 0;
}

#endif

int anti_rea_score(void) {
    int score = 0;
    g_last_hit[0] = 0;
    anti_rea_scan_env(&score);
    anti_rea_scan_parent(&score);
#if defined(_WIN32)
    anti_rea_scan_win(&score);
#else
    anti_rea_scan_posix(&score);
#endif
    if (score > ANTI_REA_MAX_SCORE) score = ANTI_REA_MAX_SCORE;
    return score;
}

const char *anti_rea_last_hit(void) { return g_last_hit[0] ? g_last_hit : "none"; }

#endif /* ANTI_REA_IMPLEMENTATION */
