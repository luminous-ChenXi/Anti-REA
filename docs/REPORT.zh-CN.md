# Anti-REA 调研报告：如何对抗 AI-Agent 驱动的逆向工程

> 版本 0.1 · 2026-10-28 · 基于 [morluto/rea](https://github.com/morluto/rea) @ `40b9c03` (2026-10-28, main) 源码级的敌情调研
> 面向读者：个人开发者 / 企业开发者，需要保护闭源商业软件（桌面 Native、Electron、.NET、Android）不被"一句话逆向"的开发者。
>
> 说明：文中 `research/rea-src/...` 路径指向 REA 仓库的本地浅克隆（体积原因不入库），
> 对应上游 commit `40b9c03`；请自行 `git clone` 后对照阅读。

---

## 1. 背景与问题定义

**REA（Reverse Engineer Anything）** 是 2026 年爆火的开源 MCP 工具（约 40 万 star）：开发者把 Claude Code/Cursor/Codex 等 AI Agent 指向任意软件的一个功能，REA 就能不依赖源码，产出伪代码、汇编、字符串、符号与"有证据支撑"的行为解释，让 Agent 直接**复刻实现**。

这对闭源/商业软件是结构性威胁：

- 原先逆向一个 Electron 应用需要专家数天；现在任何终端用户 `npx rea-agents setup` 后一句话即可；
- REA 的证据体系（observation + sha256 + 置信分级）专门为喂给 LLM 设计，LLM 再把分析结果转成可读结论——**分析成本从"专家日"降到"用户分钟"**；
- 授权校验、算法核心、协议实现这些商业软件的核心资产，正是 REA showcase 里最常被演示的目标。

**本项目的目标**：给闭源软件提供一套系统性的反逆向工程（Anti-RE）工具链，专门针对 REA 及同类 AI-Agent 逆向管线的依赖信号做消减、污染与运行时反制。

**定位与边界**：
- 这是**防御性**安全工作——保护自己的软件资产，等同于 VMProtect/Themida/OLLVM 所在的软件保护领域；
- 不追求"不可逆向"（理论上不可能），追求**把逆向成本从'用户分钟'推回到'专家周'**，并让自动化管线的产出质量塌陷；
- 不协助恶意软件逃避分析；运行时防护全部采用"打分 + 回调"设计，由软件作者自主决定响应策略。

---

## 2. REA 敌情分析（源码级）

以下结论全部来自对 `research/rea-src`（REA 完整源码）的逐模块调研，文件路径可直接查证。

### 2.1 静态原生二进制管线

| 信号 | REA 的利用方式 | 源码证据 |
|---|---|---|
| Go buildinfo 魔数 `FF 20 "Go buildinf:"` | 直接读出 Go 版本 + 全部 module 依赖清单；节名 `.go.buildinfo` 缺失时全段 fallback 扫描 | `src/native/GoBinaryProvider.ts`、`GoBuildInfoSearch.ts` |
| `/rustc/` 明文路径 | 推断 rustc 版本与 crate 特征 | `RustBinaryImage.ts` |
| `.dep-v0` 节（cargo auditable） | 完整 Rust 依赖 JSON 清单 | `RustBinaryImage.ts` |
| IL2CPP `global-metadata.dat`（magic `0xFAB11BAF`） | 恢复 Unity 类型/方法名，并作为 Ghidra 函数种子 | `Il2cppMetadataFile.ts`、`Il2cppGhidraSeeds.ts` |
| ELF `.symtab`/`.strtab` | objdump -t 枚举全部函数名；Ghidra 借符号自动命名 | `src/objdump/ObjdumpCommand.ts` |
| DWARF（`.debug_*`） | objdump -W 提取源文件路径、行号、类型 | 同上 |
| Mach-O `__objc_classlist` / `__swift5_types` | 完整恢复 ObjC 类/方法/ivar、Swift 名义类型 | `AppleObjcDispatchFacets.ts`、`AppleSwiftNominalTypes.ts` |
| PE COFF 符号表 / 调试目录 PDB 路径 | 函数名枚举、构建环境泄漏 | `src/native/pe/` |

**关键特性**：REA **没有猜测式回退**——某信号缺失时，对应 facet 诚实标注 `unavailable`，不会误判。这意味着对抗策略是**让信号消失**，而不是让信号出错（但伪造假信号污染其 evidence 同样有效，见 §4.4）。

### 2.2 托管代码 / 脚本管线

- **JS/Electron**：worker 子进程 + `@babel/parser` 全量 AST 解析（非正则）。识别 webpack（`push([[ids],{模块表},runtime])` 形状 + `__webpack_require__`）、esbuild（`__commonJS`/`__esm` 包装器名）、Next.js（`__NEXT_DATA__`/`webpackChunk_N_E`/`TURBOPACK`）。解析 `sourceMappingURL` 加载 source map；外部集成 Wakaru 做 un-minify 与模块恢复。Electron 侧读 fuse 哨兵串（`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`）、`contextBridge`/`ipcMain.handle` 通道。asar 自带解析器（头部准入预算 8MiB）。
  - **自认局限**（`JavaScriptArtifactAnalysis.ts:305`）：dynamic/obfuscated 表达式产生 `unknown_findings`，路径关系不可解析——**混淆确实使其退化，且退化为显式低置信度输出**。
- **.NET**：完全自研 PE/CLI 元数据解析器（`ManagedStaticProvider.ts`，不加载程序集不反编译 C#）：枚举 `#Strings`/`#US`/`#Blob` 堆 + 元数据表，逐 `ldstr` 解出全部字符串字面量；AssemblyRef 模式匹配识别 Unity/.NET 家族。
- **Android APK**：自解 ZIP → apktool（manifest/resources/字符串表）→ JADX bridge（dexlib2 + jadx-java 反编译）→ native .so 清单 + JNI 静态绑定 → 签名自解。支持 R8 `mapping.txt` 自动还原混淆名（`proguardMapping.ts`）。自认局限：运行时构建的 JNI 表、加密字符串、运行时加载代码**不恢复**。

### 2.3 动态分析管线与运行时足迹（反制金矿）

| 足迹 | 细节 | 源码证据 |
|---|---|---|
| **`REA_PROCESS_RUN_ID` 环境变量** | REA 启动/捕获目标进程时**强制注入**——目标进程内 `getenv` 即可检出（最硬指标） | `ProcessCaptureEnvironment.ts`、`ProcessHarness.ts` |
| 桥接变量 | Hopper bridge 等 Python 进程注入 `REA_SOCKET`/`REA_TOKEN`/`REA_RUN_ID`/`REA_TARGET_PATH` | `BridgeLauncher.ts` |
| IPC 命名 | Unix socket：`$TMPDIR/rea-provider-*/*.sock`（0700 目录）；Windows：`\\.\pipe\rea-lease-<key>` 命名管道 | `OwnedLease.ts` |
| 进程树 | 父链出现 `node … rea.mjs`；伴随 gdb/lldb/hopper/python/mitmdump/frida-server | `package.json` bin、`GdbSessionManager.ts` |
| Frida | attach/spawn 注入，脚本名固定 `rea-<uuid>`；标准 gum 痕迹（`gum-js-loop` 线程、frida-agent 映射） | `FridaInstrumentationManager.ts` |
| Windows Job Object | 受控子进程置于 Job（kill-on-close）→ `IsProcessInJob` 可探（弱信号） | `native/windows/src/process.cc` |
| 浏览器 | Playwright 持久化上下文，profile 在 `$TMPDIR/rea-browser-scenario-*`；`navigator.webdriver=true`；CDP attach | `PlaywrightScenarioBrowser.ts`、`CdpEndpoint.ts` |
| PTY | 目标经 node-pty 启动，强制 `TERM=xterm-256color` | `ProcessHarness.ts` |

### 2.4 质量与预算体系（可放大的面）

REA 的可信度建立在三级置信（`observed > derived > inferred`）与显式 limitation 上。同时它有严格的资源预算：asar 头 8MiB、单字符串表 8MiB、超预算即拒收或截断。**产出质量塌陷与资源放大都是有效对抗面**。

---

## 3. 攻击面 → 防御矩阵

| # | REA 依赖 | 防御手段 | Anti-REA 落点 | 阶段 |
|---|---|---|---|---|
| 1 | 符号表/DWARF/PDB | 内容抹除（非 ALLOC 节/COFF 表清零） | `harden`（native） | 发布期 |
| 2 | Go buildinfo/Rust 路径/dep-v0 | 魔数与路径抹除 + 节名随机化 | `harden`（native） | 发布期 |
| 3 | source map | 注释剥离 + .map 删除 | `harden`（js/asar） | 发布期 |
| 4 | webpack/esbuild/Next 哨兵 | 声明+引用一致重命名 | `harden`（js/asar） | 发布期 |
| 5 | 字符串/密钥常量 | 混淆器加密（外部工具预设）+ 人工轮换 | audit 检出 + configs 预设 | 构建/发布期 |
| 6 | .NET 元数据 | 混淆器（Obfuscar/BitMono）符号重命名+字符串加密 | audit 检出 + 文档指引 | 构建期 |
| 7 | APK dex/资源 | R8 full + 资源混淆 + JNI 动态注册 | audit 检出 + configs/r8 | 构建期 |
| 8 | REA 进程足迹（env/IPC/父子） | 运行时打分检测 + 自主响应 | `guards`（4 语言） | 运行时 |
| 9 | Frida/调试器注入 | gum 线程/映射/ptrace 检测 | `guards` | 运行时 |
| 10 | LLM 消化 evidence | 诱饵/蜜罐污染字符串空间 | `poison` | 发布期 |
| 11 | ObjC/Swift 元数据 | 构建期 strip + 反射元数据抹除（可选） | audit + `--wipe-swift-refl` | 构建/发布期 |
| 12 | 预算边界 | 巨型化/超预算结构（谨慎使用） | 文档说明（未自动化） | 发布期 |

---

## 4. 防御方法论详述

### 4.1 分层防御模型

```
构建期（最有效，改动源码/构建脚本）
├─ 符号与调试信息剥离（strip/-s -w/objcopy）
├─ 混淆器（OLLVM 系、javascript-obfuscator、Obfuscar、R8 full）
└─ 字符串常量加密/运行时派生
发布期（零源码改动，本工具主战场）
├─ anti-rea harden：二进制内容级抹除 + JS 变换 + asar 重封
└─ anti-rea poison：诱饵/蜜罐注入
运行时（最后一道）
├─ anti-rea guards：REA/Frida/调试器足迹检测（打分制）
└─ 完整性自校验 + 授权逻辑分散化
服务端（超出本工具范围，但强烈建议）
└─ 关键校验放服务端；客户端只持有短期凭证
```

**优先级建议**：构建期 > 服务端 > 发布期 > 运行时。能不进客户端的资产，永远不要进客户端。

### 4.2 发布期变换的安全边界（工程要点）

本工具的 harden 只做**内容级**变换——不改结构、不改地址、不动加载器依赖的节：
- ELF：只抹非 `SHF_ALLOC` 节内容；`.go.buildinfo` 魔数清零只影响 `debug.ReadBuildInfo()` 返回空；
- PE：COFF 符号表头字段清零 + 表区抹除；Rich header 区域保留 `MZ` 头与 `e_lfanew`；调试目录清零（loader 不读）；
- JS：哨兵标识符做**全文件一致替换**（声明与引用同步），语义不变——但会破坏依赖这些全局名的外部工具（如 HMR），故只用于发布产物；
- 所有变换默认输出到新文件，原件不动，且要求**加固后必须实际运行验证**（工具会在输出中强制提醒）。

### 4.3 运行时防护设计（guards）

四语言同构 API：`score()`（0-100 打分）+ 命中明细 + 回调。要点：
- **硬指标重罚**：`REA_PROCESS_RUN_ID`（60 分）单条即达响应线——这是 REA 架构决定的自暴露，除非 REA 改掉进程捕获注入 env 的设计（会伤其进程所有权追踪功能，改造成本高）；
- **弱指标轻罚**：Windows Job Object（8 分）大量正常软件也用，绝不单条触发；
- **默认无副作用**：库不自行崩溃/退出——由软件作者决定"记录/降级/退出/静默喂假数据"，避免误伤真实用户导致商誉损失；
- 响应策略推荐梯度：低分记录遥测 → 中分功能降级 → 高分拒绝激活 + 服务端标记。

### 4.4 LLM 对抗层（REA 特有，也是本工具的差异化）

传统 Anti-RE 只对付人和反编译器；REA 的消费端是 **LLM**，带来新的对抗面：

1. **注意力稀释（poison）**：LLM 对字符串 dump 与函数名的"语义联想"是它的加速器。掺入成体系的诱饵（假端点/假授权格式/假功能名），让 LLM 把分析预算浪费在假资产上；
2. **蜜罐触发**：诱饵常量被代码路径引用即说明有人在逆向（正常运行永远不碰）——结合 guards 可做精确报警；
3. **置信度塌陷**：REA 对"解析不了"的诚实标注意味着——混淆不追求"骗过 REA"，只需让它的输出停留在 `unknown/partial/low-confidence`，LLM 拿到的是一堆"证据不足"，复刻质量自然塌方；
4. **（进阶，未实现）反事实证据**：构造执行正确但反编译错误的指令序列（如滥用 x86 的冗余前缀/非规范路径），让伪代码与真实行为偏离——这是学术上 active 的方向，v0.2 候选。

### 4.5 学术与工业脉络

- C. Collberg 等《A Taxonomy of Obfuscating Transformations》(1997)：混淆变换分类学的奠基，本项目的"布局/数据/控制流"分层沿用该框架；
- 控制流扁平化/虚假控制流：OLLVM（2010s 开源）→ 各种衍生（Hikari/Pluto/Arkari），native 构建期混淆主流；
- 商业保护壳：VMProtect/Themida（代码虚拟化，强度最高、兼容性代价大）；
- JS 生态：javascript-obfuscator（本项目给出对抗 REA 的预设配置）、Jscrambler；
- 反调试/反插桩：ptrace 自检、`IsDebuggerPresent`、Frida 特征检测是业界成熟做法；
- 反 AI 分析是新兴方向：LLM 辅助反编译（如 LLM4Decompile 等）出现后，针对"LLM 读伪代码"的对抗（语义陷阱、注意力稀释）开始进入研究视野——Anti-REA 把它工程化。

---

## 5. Anti-REA v0.1 实现与验证

### 5.1 形态（一套核心，三种入口）

- **CLI**：`npx anti-rea audit/harden/poison/guards`，零依赖纯 Node（≥18）；
- **MCP Server**：`anti-rea mcp`（stdio JSON-RPC），暴露 `anti_rea_audit/harden/poison/guards` 四个工具——开发者对 AI Agent 说"帮我加固 dist"即可，与 REA 形成镜像对比（REA 让 Agent 逆向别人，Anti-REA 让 Agent 保护自己）；
- **Agent Skill**：`skills/anti-rea/SKILL.md`（ZCode/Claude Code 可装），固化"审计→加固→复审→运行验证"四步流程；
- **规则插件**：`anti-rea.config.json` 注册自定义检测规则（正则/包含匹配 + 严重级别），社区可共建规则库。

### 5.2 模块清单

| 模块 | 职责 |
|---|---|
| `src/formats/` | ELF/PE/Mach-O/asar 解析与受控写回（边界校验） |
| `src/audit/` | native/js/dotnet/apk 四类审计器 + 自定义规则引擎 |
| `src/harden/` | native 内容级抹除、JS/asar 变换重封 |
| `src/poison/` | 可复现诱饵生成（6 类格式） |
| `guards/` | c/c#（js/python）运行时防护库 |
| `src/mcp-server.js` | 零依赖 MCP 协议实现 |

### 5.3 验证结果（本机实测）

| 场景 | 加固前 | 加固后 | 功能验证 |
|---|---|---|---|
| Go PE（Windows，2.7MB） | 高危 2（buildinfo + 2891 项 COFF 符号表） | **高危 0** | exe 运行输出一致 ✓ |
| Go ELF（Linux） | 高危（buildinfo/symtab/DWARF 776KB/1.5MB 符号） | **0 发现** | 结构解析通过 ✓ |
| webpack 风格 JS | 高危 3（sourcemap/哨兵/密钥） | 哨兵与 sourcemap 清零（密钥项留给人工） | node 运行一致 ✓ |
| asar 归档 | sourcemap/哨兵/内嵌 map | 重封后可解析、map 移除、JS 已变换 | 提取内容校验 ✓ |
| Python guard | — | 干净环境 score=0；`REA_PROCESS_RUN_ID` 下 score=60 ✓ | — |
| MCP Server | — | initialize/tools/list/tools/call 全通 ✓ | — |
| 自定义规则 | — | 自定义 pattern 命中并按级别报告 ✓ | — |

（C 头文件与 C# 库因本机无编译器未做编译级验证，代码按保守风格编写并标注了平台差异点；欢迎社区 CI 补充。）

### 5.4 已知局限（诚实清单）

1. **harden 无法对抗所有信号**：ObjC/Swift 运行时必需的元数据、.NET 元数据表结构、wasm name section 需要构建期工具（混淆器/链接选项）配合，audit 会检出并给出指引，但不能在发布期无脑抹除；
2. **动态分析更难防**：guards 能检出 REA/Frida 的足迹，但攻击者可以改 REA 源码去掉 `REA_PROCESS_RUN_ID` 注入（开源工具，特征会漂移）——运行时防护要与其他信号组合使用，且需持续更新特征库（规则插件系统为此设计）；
3. **对抗是军备竞赛**：本报告的所有特征均来自 REA 当前源码，REA 升级可能改变行为；
4. **法律提醒**：软件保护手段在多数司法辖区合法（保护自有 IP），但请勿用于恶意软件反分析；对第三方软件使用逆向工具请遵守当地法律与许可协议。

---

## 6. 路线图（v0.2+）

- 反事实指令序列生成（让 Ghidra/IDA 伪代码与真实行为偏离）
- .NET 发布期元数据重命名（Obfuscar 集成而非仅指引）
- wasm name-section 剥离与导出裁剪
- CI 集成（GitHub Action：发布产物自动 audit 门禁）
- guards 特征库热更新（规则插件同机制）
- 更多诱饵类型（假 protobuf schema、假 RPC 接口定义）

---

## 附：参考资料

- REA 源码：`research/rea-src`（本仓库内，浅克隆自 github.com/morluto/rea）
- [Anti-Reverse Engineering — Medium](https://medium.com/@tony_write_sometimes/anti-reverse-engineering-e6adcf1ded04)
- [Automated Static Detection of Obfuscated Anti-Debugging — AFIT](https://scholar.afit.edu/cgi/viewcontent.cgi?article=1625&context=etd)
- [Anti-Reverse Engineering — Zimperium Glossary](https://zimperium.com/glossary/anti-reverse-engineering)
- [Anti-Debugging: Protect Your Apps — Preemptive](https://www.preemptive.com/blog/anti-debugging)
- Collberg, Thomborson, Low. *A Taxonomy of Obfuscating Transformations*. 1997.
- OLLVM 及衍生（控制流扁平化/虚假控制流）工业实践
