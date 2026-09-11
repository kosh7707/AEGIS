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
    // can-frame 은 ECU 가 자유 주기로 흘리므로 몇 개가 끼어드는지는 실행마다 다르다.
    // 순서를 보장해야 하는 것은 상태/정보/주입 응답 쪽이다.
    expect(parsed.types.filter((type: string) => type !== "can-frame")).toEqual([
      "ecu-status",
      "ecu-status",
      "ecu-info",
      "inject-response",
      "inject-response",
    ]);
    expect(parsed.types).toContain("can-frame");
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
