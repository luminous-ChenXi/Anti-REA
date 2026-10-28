<div align="center">

# 🛡️ Anti-REA

**让你的闭源软件对 AI-Agent 逆向工具"隐身"。**

[English](README.md) · 简体中文

</div>

---

Anti-REA 是一套零依赖、四层防御的反逆向加固工具链，针对性对抗 [REA (Reverse Engineer Anything)](https://github.com/morluto/rea) 及同类 AI-Agent 逆向管线。面向保护闭源软件的个人与企业开发者（桌面 Native / Electron / .NET / Android）。

> 完整敌情调研与防御方法论（中文，含 REA 源码级证据）：**[docs/REPORT.zh-CN.md](docs/REPORT.zh-CN.md)**

## 快速上手

```bash
npx anti-rea audit dist/          # 审计：REA 能看到你软件的哪些信号（退出码 2 = 有高危）
npx anti-rea harden dist/ --out dist-hardened/   # 加固：生成新文件，绝不改动原件
npx anti-rea audit dist-hardened/ && node dist-hardened/app.js   # 复核 + 运行验证（必须）
npx anti-rea guards emit c --out src/            # （可选）运行时防护：检出 REA/Frida/调试器
```

## 四层防御

1. **audit** — 检出 40+ 种 REA 可见信号（Go buildinfo 魔数、符号表、DWARF、PDB 路径、source map、webpack 哨兵、.NET 元数据堆、APK 资源表、明文密钥……），每条带"REA 拿它做什么 + 怎么修"。
2. **harden** — 内容级安全变换（不改结构/地址/运行语义）：抹符号表与调试节、清 Go buildinfo、剥 source map、重命名框架哨兵、asar 提取-加固-重封。输出新文件 + 强制运行验证提醒。
3. **poison** — 可复现诱饵（假端点/假授权格式/蜜罐标记），稀释逆向 LLM 注意力，蜜罐被触碰即报警。
4. **guards** — C/C++、C#、JS、Python 四语言运行时防护（0-100 打分，默认无副作用）：检出 `REA_PROCESS_RUN_ID` 环境变量、`rea-provider-*` IPC、分析工具父进程链、Frida 注入。

## 三种入口

- **CLI**：如上。
- **MCP Server**：`anti-rea mcp`，任意 AI Agent 一句话调用（与 REA 镜像：它帮人逆向，Anti-REA 帮人自保）。配置见 [英文 README](README.md#use-it-from-your-ai-agent-mcp)。
- **Agent Skill**：[skills/anti-rea/SKILL.md](skills/anti-rea/SKILL.md)，固化"审计→加固→复审→运行验证"流程。

## 更多

- 自定义规则插件：`anti-rea.config.json`（[示例](configs/anti-rea.example.config.json)）
- 混淆器预设：[configs/javascript-obfuscator.preset.json](configs/javascript-obfuscator.preset.json)
- 实测数据、安全模型、威胁模型与 FAQ：见 [英文 README](README.md)

## License

[MIT](LICENSE)
