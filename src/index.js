// Anti-REA library entry point — programmatic API.
// CLI: bin/anti-rea.mjs · MCP server: src/mcp-server.js
export { runCli } from "./cli.js";
export { startMcpServer } from "./mcp-server.js";
export { auditPath, auditFile, summarize, renderReport, detectFileKind, loadCustomRules, applyCustomRules } from "./audit/index.js";
export { hardenNative } from "./harden/native.js";
export { hardenJsFile, hardenJsTree, hardenAsar, transformJsText } from "./harden/javascript.js";
export { generateDecoys, renderDecoys } from "./poison/index.js";
export { GUARDS } from "./guards.js";
