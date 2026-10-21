import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { RegisteredSdk, SdkAnalyzedProfile } from "@aegis/shared";
import { SdkService } from "../sdk.service";

function makeTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "aegis-sdk-service-"));
}

function createTarArchive(root: string, archiveName: string): { archivePath: string; originalName: string } {
  const sourceDir = path.join(root, "src");
  fs.mkdirSync(path.join(sourceDir, "sdk-root"), { recursive: true });
  fs.writeFileSync(path.join(sourceDir, "sdk-root", "README.txt"), "hello");
  const archivePath = path.join(root, archiveName);
  execFileSync("tar", ["-cf", archivePath, "-C", sourceDir, "sdk-root"]);
  return { archivePath, originalName: archiveName };
}

function createInstaller(root: string, name: string, mode: "success" | "success-verbose" | "success-heartbeat" | "fail"): { installerPath: string; originalName: string } {
  const installerPath = path.join(root, name);
  const successBody = mode === "success-verbose"
    ? `#!/bin/sh
set -eu
prefix=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) shift; prefix="$1" ;;
  esac
  shift || true
done
echo "installer boot"
mkdir -p "$prefix"/ti-sdk
printf 'ok' > "$prefix"/ti-sdk/installed.txt
echo "installer done"
`
    : mode === "success-heartbeat"
      ? `#!/bin/sh
set -eu
prefix=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) shift; prefix="$1" ;;
  esac
  shift || true
done
mkdir -p "$prefix"/ti-sdk
sleep 0.08
printf 'ok' > "$prefix"/ti-sdk/installed.txt
`
      : `#!/bin/sh
set -eu
prefix=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix) shift; prefix="$1" ;;
  esac
  shift || true
done
mkdir -p "$prefix"/ti-sdk
printf 'ok' > "$prefix"/ti-sdk/installed.txt
`;
  const failureBody = `#!/bin/sh
echo "install failed" 1>&2
exit 23
`;
  const script = mode === "fail" ? failureBody : successBody;
  fs.writeFileSync(installerPath, script, { mode: 0o755 });
  return { installerPath, originalName: name };
}

describe("SdkService", () => {
  let uploadsDir: string;
  let records: Map<string, RegisteredSdk>;
  let dao: any;
  let buildAgentClient: any;
  let sdkWs: any;
  let notificationService: any;
  let service: SdkService;

  beforeEach(() => {
    delete process.env.AEGIS_SDK_INSTALL_HEARTBEAT_MS;
    delete process.env.AEGIS_SDK_INSTALL_TIMEOUT_MS;
    uploadsDir = makeTempDir();
    records = new Map<string, RegisteredSdk>();
    dao = {
      save: vi.fn((sdk: RegisteredSdk) => records.set(sdk.id, {
        ...sdk,
        currentPhaseStartedAt: Date.now(),
        phaseHistory: sdk.phaseHistory ?? [{ phase: sdk.status, startedAt: Date.now() }],
        retryCount: sdk.retryCount ?? 0,
        retryable: false,
      })),
      findByProjectId: vi.fn((projectId: string) => [...records.values()].filter((sdk) => sdk.projectId === projectId)),
      findById: vi.fn((id: string) => records.get(id)),
      updateStatus: vi.fn((id: string, status: RegisteredSdk["status"], verifyError?: string) => {
        const sdk = records.get(id);
        if (!sdk) return;
        const nowMs = Date.now();
        const phaseHistory = [...(sdk.phaseHistory ?? [])];
        const last = phaseHistory.length > 0 ? phaseHistory[phaseHistory.length - 1] : undefined;
        if (last && !last.endedAt) {
          last.endedAt = nowMs;
          last.durationMs = Math.max(0, nowMs - last.startedAt);
        }
        phaseHistory.push({ phase: status, startedAt: nowMs });
        records.set(id, {
          ...sdk,
          status,
          verifyError,
          verified: status === "ready",
          currentPhaseStartedAt: nowMs,
          phaseHistory,
          retryable: (status === "extract_failed" || status === "install_failed" || status === "verify_failed")
            && fs.existsSync(sdk.path),
          retryExpiresAt: status.endsWith("_failed") ? nowMs + 24 * 60 * 60 * 1000 : sdk.retryExpiresAt,
          updatedAt: new Date().toISOString(),
        });
      }),
      incrementRetry: vi.fn((id: string, retryExpiresAt?: number) => {
        const sdk = records.get(id);
        if (!sdk) return;
        records.set(id, {
          ...sdk,
          retryCount: (sdk.retryCount ?? 0) + 1,
          retryExpiresAt,
          updatedAt: new Date(Date.now() - 31_000).toISOString(),
        });
      }),
      updateProfile: vi.fn((id: string, profile: SdkAnalyzedProfile) => {
        const sdk = records.get(id);
        if (!sdk) return;
        records.set(id, {
          ...sdk,
          profile,
          artifactKind: profile.artifactKind,
          sdkVersion: profile.sdkVersion,
          targetSystem: profile.targetSystem,
          installLogPath: profile.installLogPath,
          updatedAt: new Date().toISOString(),
        });
      }),
      updatePath: vi.fn((id: string, sdkPath: string) => {
        const sdk = records.get(id);
        if (!sdk) return;
        records.set(id, { ...sdk, path: sdkPath, updatedAt: new Date().toISOString() });
      }),
      delete: vi.fn((id: string) => records.delete(id)),
    };
    buildAgentClient = {
      submitTask: vi.fn().mockResolvedValue({
        success: true,
        result: {
          sdkProfile: {
            compilerPrefix: "arm-none-eabi-",
            gccVersion: "13.2.0",
            targetArch: "armv7-a",
          },
        },
      }),
      isSuccess: vi.fn().mockReturnValue(true),
    };
    sdkWs = { broadcast: vi.fn() };
    notificationService = { emit: vi.fn() };
    service = new SdkService(
      dao,
      buildAgentClient,
      uploadsDir,
      sdkWs,
      notificationService,
    );
  });

  afterEach(() => {
    delete process.env.AEGIS_SDK_INSTALL_HEARTBEAT_MS;
    delete process.env.AEGIS_SDK_INSTALL_TIMEOUT_MS;
    fs.rmSync(uploadsDir, { recursive: true, force: true });
  });

  it("extracts archive uploads into project-scoped content, deletes the artifact, and emits sdk_ready", async () => {
    const { archivePath, originalName } = createTarArchive(uploadsDir, "ti-sdk-am335x-08.02.00.24.tar");

    await service.register("p-sdk", {
      sdkId: "sdk-archive",
      name: "TI SDK",
      files: [{ originalName, storedPath: archivePath, size: fs.statSync(archivePath).size }],
    }, "req-sdk-archive");

    await vi.waitFor(() => expect(dao.updateStatus).toHaveBeenCalledWith("sdk-archive", "ready"));

    const stored = records.get("sdk-archive")!;
    expect(stored.path).toContain(path.join(uploadsDir, "p-sdk", "sdk", "sdk-archive"));
    expect(fs.existsSync(archivePath)).toBe(false);
    expect(fs.existsSync(path.join(stored.path, "README.txt"))).toBe(true);
    expect(stored.artifactKind).toBe("archive");
    expect(stored.sdkVersion).toBe("08.02.00.24");
    expect(stored.targetSystem).toBe("am335x");
    expect(stored.currentPhaseStartedAt).toEqual(expect.any(Number));
    expect(stored.phaseHistory?.map((entry) => entry.phase)).toEqual(
      expect.arrayContaining(["uploaded", "extracting", "extracted", "analyzing", "verifying", "ready"]),
    );
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-sdk", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({
        sdkId: "sdk-archive",
        phase: "uploaded",
        phaseStartedAt: expect.any(Number),
        phaseDetail: expect.objectContaining({ kind: "sdk.uploaded" }),
      }),
    }));
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-sdk", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({ sdkId: "sdk-archive", phase: "extracting" }),
    }));
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-sdk", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({ sdkId: "sdk-archive", phase: "extracted" }),
    }));
    expect(notificationService.emit).toHaveBeenCalledWith(expect.objectContaining({
      projectId: "p-sdk",
      type: "sdk_ready",
      jobKind: "sdk",
      resourceId: "sdk-archive",
      correlationId: "sdk-archive",
    }));
    expect(notificationService.emit.mock.calls.filter(([payload]: any[]) => payload.type === "sdk_ready")).toHaveLength(1);
    expect(buildAgentClient.submitTask).toHaveBeenCalledWith(
      expect.objectContaining({
        taskType: "sdk-analyze",
        constraints: { timeoutMs: 300000 },
      }),
      "req-sdk-archive",
    );
  });

  it("executes .bin installers into project-scoped installed output and persists install log path", async () => {
    const { installerPath, originalName } = createInstaller(uploadsDir, "ti-processor-sdk-linux-am335x-evm-08.02.00.24.bin", "success-verbose");

    await service.register("p-bin", {
      sdkId: "sdk-bin",
      name: "TI Installer",
      files: [{ originalName, storedPath: installerPath, size: fs.statSync(installerPath).size }],
    }, "req-sdk-bin");

    await vi.waitFor(() => expect(dao.updateStatus).toHaveBeenCalledWith("sdk-bin", "ready"));

    const stored = records.get("sdk-bin")!;
    expect(stored.path).toContain(path.join(uploadsDir, "p-bin", "sdk", "sdk-bin", "installed"));
    expect(fs.existsSync(path.join(stored.path, "installed.txt"))).toBe(true);
    expect(stored.installLogPath).toContain(path.join(uploadsDir, "p-bin", "sdk", "sdk-bin", "install.log"));
    const installLog = fs.readFileSync(stored.installLogPath!, "utf-8");
    expect(installLog).toContain("upload completed");
    expect(installLog).toContain("install started");
    expect(installLog).toContain("installer boot");
    expect(installLog).toContain("installer done");
    expect(installLog).toContain("install completed");
    expect(stored.artifactKind).toBe("bin");
    expect(stored.sdkVersion).toBe("08.02.00.24");
    expect(stored.targetSystem).toBe("am335x-evm");
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-bin", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({ sdkId: "sdk-bin", phase: "installing" }),
    }));
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-bin", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({ sdkId: "sdk-bin", phase: "installed" }),
    }));
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-bin", expect.objectContaining({
      type: "sdk-log",
      payload: expect.objectContaining({ sdkId: "sdk-bin", source: "installer", kind: "output" }),
    }));
  });

  it("retries ETXTBSY when the uploaded installer is still open for writing", async () => {
    const { installerPath, originalName } = createInstaller(uploadsDir, "ti-processor-sdk-linux-am335x-evm-08.02.00.24.bin", "success");
    const installerFd = fs.openSync(installerPath, "r+");
    setTimeout(() => {
      fs.closeSync(installerFd);
    }, 350);

    await service.register("p-bin-busy", {
      sdkId: "sdk-bin-busy",
      name: "TI Installer Busy",
      files: [{ originalName, storedPath: installerPath, size: fs.statSync(installerPath).size }],
    }, "req-sdk-bin-busy");

    await vi.waitFor(() => expect(dao.updateStatus).toHaveBeenCalledWith("sdk-bin-busy", "ready"));

    const stored = records.get("sdk-bin-busy")!;
    expect(fs.existsSync(path.join(stored.path, "installed.txt"))).toBe(true);
    expect(stored.status).toBe("ready");
  });

  it("writes lifecycle heartbeat lines even when installer output is silent", async () => {
    process.env.AEGIS_SDK_INSTALL_HEARTBEAT_MS = "10";
    const { installerPath, originalName } = createInstaller(uploadsDir, "ti-processor-sdk-linux-am335x-evm-heartbeat.bin", "success-heartbeat");

    await service.register("p-bin-heartbeat", {
      sdkId: "sdk-bin-heartbeat",
      name: "TI Installer Heartbeat",
      files: [{ originalName, storedPath: installerPath, size: fs.statSync(installerPath).size }],
    }, "req-sdk-bin-heartbeat");

    await vi.waitFor(() => expect(dao.updateStatus).toHaveBeenCalledWith("sdk-bin-heartbeat", "ready"));

    const stored = records.get("sdk-bin-heartbeat")!;
    const installLog = fs.readFileSync(stored.installLogPath!, "utf-8");
    expect(installLog).toContain("install heartbeat");
    expect(installLog).toContain("childAlive=true");
  });

  it("surfaces extraction failures through sdk-error and sdk_failed notification", async () => {
    const badArchive = path.join(uploadsDir, "broken-sdk.tar.gz");
    fs.writeFileSync(badArchive, "not an archive");

    await service.register("p-bad", {
      sdkId: "sdk-bad",
      name: "Broken SDK",
      files: [{ originalName: "broken-sdk.tar.gz", storedPath: badArchive, size: fs.statSync(badArchive).size }],
    }, "req-sdk-bad");

    await vi.waitFor(() => expect(dao.updateStatus).toHaveBeenCalledWith("sdk-bad", "extract_failed", expect.any(String)));

    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-bad", expect.objectContaining({
      type: "sdk-error",
      payload: expect.objectContaining({
        sdkId: "sdk-bad",
        phase: "extract_failed",
        code: "EXTRACT_FAILED",
        retryable: false,
        recoverable: false,
        troubleshootingUrl: "https://github.com/kosh7707/AEGIS/blob/main/docs/troubleshooting/sdk.md#extract-failed",
      }),
    }));
    expect(notificationService.emit).toHaveBeenCalledWith(expect.objectContaining({
      projectId: "p-bad",
      type: "sdk_failed",
      resourceId: "sdk-bad",
    }));
    expect(fs.existsSync(badArchive)).toBe(true);
  });

  it("surfaces installer failures with install_failed and keeps the installer for debugging", async () => {
    const { installerPath, originalName } = createInstaller(uploadsDir, "broken-installer.bin", "fail");

    await service.register("p-fail", {
      sdkId: "sdk-fail",
      name: "Broken Installer",
      files: [{ originalName, storedPath: installerPath, size: fs.statSync(installerPath).size }],
    }, "req-sdk-fail");

    await vi.waitFor(() => expect(dao.updateStatus).toHaveBeenCalledWith("sdk-fail", "install_failed", expect.any(String)));

    const stored = records.get("sdk-fail")!;
    expect(stored.installLogPath).toContain("install.log");
    expect(fs.existsSync(installerPath)).toBe(true);
    const installLog = fs.readFileSync(stored.installLogPath!, "utf-8");
    expect(installLog).toContain("install failed");
    expect(installLog).toContain("installer process exited with failure");
    expect(installLog).toContain("install failed | phase=install_failed");
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-fail", expect.objectContaining({
      type: "sdk-error",
      payload: expect.objectContaining({
        sdkId: "sdk-fail",
        phase: "install_failed",
        logPath: expect.stringContaining("install.log"),
        code: "INSTALL_PROCESS_FAILED",
        retryable: true,
      }),
    }));
    expect(notificationService.emit.mock.calls.filter(([payload]: any[]) => payload.type === "sdk_failed")).toHaveLength(1);
  });

  it("materializes folder uploads into canonical content and keeps project-scoped metadata", async () => {
    const first = path.join(uploadsDir, "one.txt");
    const second = path.join(uploadsDir, "two.txt");
    fs.writeFileSync(first, "one");
    fs.writeFileSync(second, "two");

    await service.register("p-folder", {
      sdkId: "sdk-folder",
      name: "Folder SDK",
      files: [
        { originalName: "one.txt", relativePath: "dir/one.txt", storedPath: first, size: 3 },
        { originalName: "two.txt", relativePath: "dir/sub/two.txt", storedPath: second, size: 3 },
      ],
    });

    await vi.waitFor(() => expect(dao.updateStatus).toHaveBeenCalledWith("sdk-folder", "ready"));

    const stored = records.get("sdk-folder")!;
    expect(stored.artifactKind).toBe("folder");
    expect(stored.path).toContain(path.join(uploadsDir, "p-folder", "sdk", "sdk-folder"));
    expect(fs.existsSync(path.join(stored.path, "one.txt"))).toBe(true);
    expect(fs.existsSync(path.join(stored.path, "sub", "two.txt"))).toBe(true);
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-folder", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({ sdkId: "sdk-folder", phase: "extracting" }),
    }));
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-folder", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({ sdkId: "sdk-folder", phase: "extracted" }),
    }));
  });

  it("retries failed materialized SDKs and preserves retry counters", async () => {
    const sdkPath = path.join(uploadsDir, "p-retry", "sdk", "sdk-retry", "content");
    fs.mkdirSync(sdkPath, { recursive: true });
    fs.writeFileSync(path.join(sdkPath, "README.txt"), "ok");
    records.set("sdk-retry", {
      id: "sdk-retry",
      projectId: "p-retry",
      name: "Retry SDK",
      path: sdkPath,
      profile: { artifactKind: "archive" },
      status: "verify_failed",
      verified: false,
      retryCount: 0,
      retryable: true,
      retryExpiresAt: Date.now() + 60_000,
      phaseHistory: [{ phase: "verify_failed", startedAt: Date.now() - 60_000, endedAt: Date.now() - 31_000, durationMs: 29_000 }],
      currentPhaseStartedAt: Date.now() - 31_000,
      createdAt: new Date(Date.now() - 60_000).toISOString(),
      updatedAt: new Date(Date.now() - 31_000).toISOString(),
    });

    const retried = await service.retry("sdk-retry", "verifying", "req-retry");

    expect(dao.incrementRetry).toHaveBeenCalledWith("sdk-retry", expect.any(Number));
    expect(retried.status).toBe("ready");
    expect(retried.retryCount).toBe(1);
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-retry", expect.objectContaining({
      type: "sdk-progress",
      payload: expect.objectContaining({ sdkId: "sdk-retry", phase: "verifying", phaseDetail: { kind: "sdk.verifying.retry" } }),
    }));
    expect(sdkWs.broadcast).toHaveBeenCalledWith("p-retry", expect.objectContaining({
      type: "sdk-complete",
      payload: expect.objectContaining({ sdkId: "sdk-retry", path: sdkPath }),
    }));
  });
});
