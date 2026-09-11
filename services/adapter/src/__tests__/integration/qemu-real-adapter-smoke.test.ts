import fs from "fs";
import path from "path";
import { spawn, type ChildProcessByStdio } from "child_process";
import type { Readable } from "stream";
import { afterEach, describe, expect, it } from "vitest";

const adapterRoot = path.resolve(__dirname, "../../..");
const repoRoot = path.resolve(adapterRoot, "../..");
const ecuOutDir = path.join(repoRoot, "services", "ecu-simulator", "qemu", "out");

describe("adapter qemu smoke cli", () => {
  let child: ChildProcessByStdio<null, Readable, Readable> | null = null;

  afterEach(async () => {
    if (child && child.exitCode === null) {
      child.kill("SIGTERM");
      await onceExit(child);
    }
    child = null;
    cleanupCompiledArtifacts();
  });

  it("runs the real adapter smoke flow and returns expected qemu bridge evidence", async () => {
    const result = await new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
      child = spawn("npm", ["run", "qemu:smoke:sample"], {
        cwd: adapterRoot,
        env: {
          ...process.env,
          LOG_LEVEL: "silent",
        },
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";

      child.stdout.on("data", (chunk) => {
        stdout += chunk.toString();
      });

      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });

      child.on("exit", (code) => {
        if (code !== 0) {
          reject(new Error(`qemu smoke cli failed with code ${code}\n${stdout}\n${stderr}`));
          return;
        }
        resolve({ stdout, stderr });
      });
    });

    // npm 12 는 실행 시 `npm notice run ...` 을 stderr 로 내보내므로 CLI 자체 출력만 검사
    expect(result.stderr.replace(/^npm notice.*$/gm, "").trim()).toBe("");

    const parsed = parseLastJsonObject(result.stdout);
    expect(parsed.types).toEqual([
      "ecu-status",
      "ecu-status",
      "ecu-info",
      "can-frame",
      "inject-response",
      "can-frame",
      "inject-response",
    ]);
    expect(parsed.ecuInfo.ecu.name).toBe("QEMU_SAMPLE_MANIFEST");
    expect(parsed.firstResponse.response.success).toBe(true);
    expect(parsed.secondResponse.response.success).toBe(true);
  }, 20000);
});

function parseLastJsonObject(output: string): any {
  const lines = output
    .trim()
    .split("\n")
    .map((line) => line.trimEnd());

  const startIndex = lines.findIndex((line) => line.trimStart().startsWith("{"));
  if (startIndex < 0) {
    throw new Error(`No JSON object found in output:\n${output}`);
  }

  return JSON.parse(lines.slice(startIndex).join("\n"));
}

function cleanupCompiledArtifacts(): void {
  for (const fileName of ["sample-ecu-armhf", "sample-ecu-armhf.o"]) {
    const filePath = path.join(ecuOutDir, fileName);
    if (fs.existsSync(filePath)) {
      try {
        fs.unlinkSync(filePath);
      } catch {
        // ignore cleanup failure
      }
    }
  }
}

function onceExit(childProcess: ChildProcessByStdio<null, Readable, Readable>): Promise<void> {
  return new Promise((resolve) => {
    if (childProcess.exitCode !== null) {
      resolve();
      return;
    }
    childProcess.once("exit", () => resolve());
  });
}
