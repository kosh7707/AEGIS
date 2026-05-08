import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { BuildTargetCreateDialog } from "./BuildTargetCreateDialog";
import { ApiError } from "@/common/api/core";
import type { SourceFileEntry } from "@/common/api/client";

const { mockToast, mockBuildTargetsAdd } = vi.hoisted(() => ({
  mockToast: { error: vi.fn(), warning: vi.fn(), success: vi.fn() },
  mockBuildTargetsAdd: vi.fn(),
}));

// Mock dependencies
vi.mock("@/common/hooks/useBuildTargets", () => ({
  useBuildTargets: () => ({
    targets: [],
    loading: false,
    add: mockBuildTargetsAdd,
    remove: vi.fn(),
    update: vi.fn(),
    discover: vi.fn(),
  }),
}));
vi.mock("@/common/contexts/ToastContext", () => ({
  useToast: () => mockToast,
}));

vi.mock("@/common/api/client", () => ({
  logError: vi.fn(),
}));

beforeEach(() => {
  mockToast.error.mockReset();
  mockToast.warning.mockReset();
  mockToast.success.mockReset();
  mockBuildTargetsAdd.mockReset();
});

vi.mock("@/common/api/sdk", () => ({
  fetchProjectSdks: vi.fn().mockResolvedValue({ builtIn: [], registered: [] }),
}));

const mockFiles: SourceFileEntry[] = [
  { relativePath: "src/main.c", size: 1024, language: "C" },
  { relativePath: "src/utils.c", size: 512, language: "C" },
  { relativePath: "include/utils.h", size: 256, language: "C" },
];

const defaultProps = {
  open: true,
  projectId: "p-1",
  sourceFiles: mockFiles,
  onCreated: vi.fn(),
  onCancel: vi.fn(),
};

describe("BuildTargetCreateDialog", () => {
  it("renders nothing when open=false", () => {
    const { container } = render(
      <BuildTargetCreateDialog {...defaultProps} open={false} />,
    );
    expect(container.innerHTML).toBe("");
  });

  it("renders name input and file tree when open", async () => {
    render(<BuildTargetCreateDialog {...defaultProps} />);

    await waitFor(() => expect(screen.getAllByText("src").length).toBeGreaterThan(0));
    expect(screen.getAllByText("BuildTarget 생성").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByPlaceholderText("예: gateway-module")).toBeTruthy();
    expect(screen.getByText("포함할 파일/폴더 선택")).toBeTruthy();
    // File trees should show folder names (now appears in both includedPaths and scriptHint trees)
    expect(screen.getAllByText("src").length).toBeGreaterThan(0);
    expect(screen.getAllByText("include").length).toBeGreaterThan(0);
  });

  it("keeps cancel scoped to explicit cancel actions and the overlay", () => {
    const onCancel = vi.fn();
    render(<BuildTargetCreateDialog {...defaultProps} onCancel={onCancel} />);

    fireEvent.click(screen.getByText("BuildTarget 이름"));
    expect(onCancel).not.toHaveBeenCalled();

    fireEvent.click(screen.getByText("취소"));
    expect(onCancel).toHaveBeenCalledTimes(1);

    onCancel.mockClear();
    fireEvent.click(document.querySelector(".confirm-overlay")!);
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it("keeps submit disabled until at least one source path is selected", async () => {
    render(<BuildTargetCreateDialog {...defaultProps} />);

    const submit = screen.getByRole("button", { name: "BuildTarget 생성" });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getAllByText("main.c")[0]);
    await waitFor(() => expect(submit).not.toBeDisabled());
  });

  it("shows selected file count", async () => {
    render(<BuildTargetCreateDialog {...defaultProps} />);

    await waitFor(() => expect(screen.getByText(/0개 파일/)).toBeTruthy());
    // Initially 0 selected
    expect(screen.getByText(/0개 파일/)).toBeTruthy();

    // Click on a file to select it (first match = includedPaths tree)
    fireEvent.click(screen.getAllByText("main.c")[0]);
    await waitFor(() => expect(screen.getByText(/1개 파일/)).toBeTruthy());
  });

  it("preloads includedPaths in edit mode and submits updated payload (when explicitly editable)", () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(
      <BuildTargetCreateDialog
        {...defaultProps}
        title="BuildTarget 수정"
        submitLabel="저장"
        initialName="gateway"
        initialIncludedPaths={["src/"]}
        includedPathsEditable={true}
        onSubmit={onSubmit}
      />,
    );

    expect(screen.getByText(/2개 파일/)).toBeTruthy();

    fireEvent.click(screen.getAllByText("utils.h")[0]);
    fireEvent.click(screen.getByText("저장"));

    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
      name: "gateway",
      includedPaths: expect.arrayContaining(["src/main.c", "src/utils.c", "include/utils.h"]),
    }));
  });

  it("auto-locks includedPaths selection when onSubmit is provided (edit mode default)", () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(
      <BuildTargetCreateDialog
        {...defaultProps}
        title="BuildTarget 수정"
        submitLabel="저장"
        initialName="gateway"
        initialIncludedPaths={["src/"]}
        onSubmit={onSubmit}
      />,
    );

    const notes = screen.getAllByRole("note");
    expect(notes.some((n) => n.textContent?.includes("includedPaths는 수정 API에서 갱신되지 않습니다"))).toBe(true);

    fireEvent.click(screen.getAllByText("utils.h")[0]);
    fireEvent.click(screen.getByText("저장"));
    expect(onSubmit.mock.calls[0]?.[0].includedPaths).not.toContain("include/utils.h");
  });

  it("locks includedPaths selection when edit support is disabled", () => {
    const onSubmit = vi.fn().mockResolvedValue(undefined);
    render(
      <BuildTargetCreateDialog
        {...defaultProps}
        title="BuildTarget 수정"
        submitLabel="저장"
        initialName="gateway"
        initialIncludedPaths={["src/"]}
        includedPathsEditable={false}
        onSubmit={onSubmit}
      />,
    );

    const notes = screen.getAllByRole("note");
    expect(notes.some((n) => n.textContent?.includes("includedPaths는 수정 API에서 갱신되지 않습니다"))).toBe(true);
    expect(screen.getByText(/2개 파일/)).toBeTruthy();

    fireEvent.click(screen.getAllByText("utils.h")[0]);
    expect(screen.getByText(/2개 파일/)).toBeTruthy();

    fireEvent.click(screen.getByText("저장"));
    expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
      name: "gateway",
      includedPaths: expect.arrayContaining(["src/main.c", "src/utils.c"]),
    }));
    expect(onSubmit.mock.calls[0]?.[0].includedPaths).not.toContain("include/utils.h");
  });

  describe("scriptHintPath surface", () => {
    it("renders the script hint section with placeholder when nothing is picked", () => {
      render(<BuildTargetCreateDialog {...defaultProps} />);
      expect(screen.getByText("빌드 스크립트 힌트 (선택)")).toBeInTheDocument();
      expect(screen.getByText("선택된 파일 없음")).toBeInTheDocument();
    });

    it("forwards picked scriptHintPath in onSubmit payload, root-stripped against the typed name", () => {
      const onSubmit = vi.fn().mockResolvedValue(undefined);
      render(
        <BuildTargetCreateDialog
          {...defaultProps}
          submitLabel="저장"
          includedPathsEditable={true}
          onSubmit={onSubmit}
        />,
      );

      fireEvent.change(screen.getByPlaceholderText("예: gateway-module"), { target: { value: "src" } });
      fireEvent.click(screen.getAllByText("main.c")[0]);

      const radiogroup = screen.getByRole("radiogroup");
      fireEvent.click(within(radiogroup).getByText("main.c"));

      fireEvent.click(screen.getByText("저장"));

      expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
        name: "src",
        scriptHintPath: "main.c",
      }));
    });

    it("forwards scriptHintPath:null when nothing is picked", () => {
      const onSubmit = vi.fn().mockResolvedValue(undefined);
      render(
        <BuildTargetCreateDialog
          {...defaultProps}
          submitLabel="저장"
          includedPathsEditable={true}
          onSubmit={onSubmit}
        />,
      );

      fireEvent.change(screen.getByPlaceholderText("예: gateway-module"), { target: { value: "gateway" } });
      fireEvent.click(screen.getAllByText("main.c")[0]);
      fireEvent.click(screen.getByText("저장"));

      expect(onSubmit).toHaveBeenCalledWith(expect.objectContaining({
        scriptHintPath: null,
      }));
    });

    it("preloads initialScriptHintPath in edit mode and reconstructs the uploaded path", () => {
      render(
        <BuildTargetCreateDialog
          {...defaultProps}
          title="BuildTarget 수정"
          submitLabel="저장"
          initialName="src"
          initialRelativePath="src/"
          initialScriptHintPath="main.c"
          onSubmit={vi.fn().mockResolvedValue(undefined)}
        />,
      );

      const card = screen.getByTestId("script-hint-selected");
      expect(card).toHaveTextContent("src/main.c");
    });

    it("clear button resets the selection", () => {
      render(
        <BuildTargetCreateDialog
          {...defaultProps}
          initialName="src"
          initialRelativePath="src/"
          initialScriptHintPath="main.c"
          onSubmit={vi.fn().mockResolvedValue(undefined)}
        />,
      );

      expect(screen.getByTestId("script-hint-selected")).toBeInTheDocument();
      fireEvent.click(screen.getByLabelText("선택 해제"));
      expect(screen.queryByTestId("script-hint-selected")).not.toBeInTheDocument();
      expect(screen.getByText("선택된 파일 없음")).toBeInTheDocument();
    });

    it("surfaces a script-hint-specific toast on 400 INVALID_INPUT", async () => {
      mockBuildTargetsAdd.mockRejectedValueOnce(
        new ApiError("입력값이 올바르지 않습니다.", "INVALID_INPUT", false, "req-1"),
      );

      render(<BuildTargetCreateDialog {...defaultProps} />);

      fireEvent.change(screen.getByPlaceholderText("예: gateway-module"), { target: { value: "src" } });
      fireEvent.click(screen.getAllByText("main.c")[0]);
      const radiogroup = screen.getByRole("radiogroup");
      fireEvent.click(within(radiogroup).getByText("main.c"));

      fireEvent.click(screen.getByRole("button", { name: "BuildTarget 생성" }));

      await waitFor(() => {
        expect(mockToast.error).toHaveBeenCalledWith(
          expect.stringContaining("빌드 스크립트 힌트로 사용할 수 없습니다"),
        );
      });
    });

    it("prefers ApiError.detailMessage over hint-specific text when backend supplies a reason", async () => {
      mockBuildTargetsAdd.mockRejectedValueOnce(
        new ApiError(
          "입력값이 올바르지 않습니다.",
          "INVALID_INPUT",
          false,
          "req-1",
          "name 필드는 필수입니다.",
        ),
      );

      render(<BuildTargetCreateDialog {...defaultProps} />);

      fireEvent.change(screen.getByPlaceholderText("예: gateway-module"), { target: { value: "src" } });
      fireEvent.click(screen.getAllByText("main.c")[0]);
      const radiogroup = screen.getByRole("radiogroup");
      fireEvent.click(within(radiogroup).getByText("main.c"));

      fireEvent.click(screen.getByRole("button", { name: "BuildTarget 생성" }));

      await waitFor(() => {
        expect(mockToast.error).toHaveBeenCalledWith("name 필드는 필수입니다.");
      });
      expect(mockToast.error).not.toHaveBeenCalledWith(
        expect.stringContaining("빌드 스크립트 힌트로 사용할 수 없습니다"),
      );
    });

    it("strips a leading slash from initialScriptHintPath when reconstructing the uploaded path (defensive)", () => {
      render(
        <BuildTargetCreateDialog
          {...defaultProps}
          title="BuildTarget 수정"
          submitLabel="저장"
          initialName="src"
          initialRelativePath="src/"
          initialScriptHintPath="/main.c"
          onSubmit={vi.fn().mockResolvedValue(undefined)}
        />,
      );

      const card = screen.getByTestId("script-hint-selected");
      expect(card).toHaveTextContent("src/main.c");
      expect(card).not.toHaveTextContent("src//main.c");
    });

    it("uses the generic failure toast for non-script INVALID_INPUT (no hint picked)", async () => {
      mockBuildTargetsAdd.mockRejectedValueOnce(
        new ApiError("입력값이 올바르지 않습니다.", "INVALID_INPUT", false, "req-1"),
      );

      render(<BuildTargetCreateDialog {...defaultProps} />);

      fireEvent.change(screen.getByPlaceholderText("예: gateway-module"), { target: { value: "src" } });
      fireEvent.click(screen.getAllByText("main.c")[0]);

      fireEvent.click(screen.getByRole("button", { name: "BuildTarget 생성" }));

      await waitFor(() => {
        expect(mockToast.error).toHaveBeenCalledWith("BuildTarget 생성에 실패했습니다.");
      });
    });
  });
});
