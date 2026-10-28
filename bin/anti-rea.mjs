#!/usr/bin/env node
// Anti-REA CLI entry — zero dependencies, plain Node ESM.
import { runCli } from "../src/cli.js";

process.exitCode = await runCli(process.argv.slice(2));
