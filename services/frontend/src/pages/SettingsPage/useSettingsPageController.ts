import { useCallback, useEffect, useMemo, useState } from "react";
import { getBackendUrl, healthCheck, healthFetch, setBackendUrl, type LlmGatewayHealthEntry } from "@/common/api/client";
import { applyTheme, getThemePreference, setThemePreference, type ThemePreference } from "@/common/utils/theme";

export type TestStatus = "idle" | "testing" | "ok" | "error";

export function useSettingsPageController() {
  const [url, setUrl] = useState(getBackendUrl);
  const [storedUrl, setStoredUrl] = useState(getBackendUrl);
  const [saved, setSaved] = useState(false);
  const [testStatus, setTestStatus] = useState<TestStatus>("idle");
  const [testDetail, setTestDetail] = useState("");
  const [theme, setTheme] = useState<ThemePreference>(getThemePreference);
  const [storedTheme, setStoredTheme] = useState<ThemePreference>(getThemePreference);
  const [llmGateway, setLlmGateway] = useState<LlmGatewayHealthEntry | null>(null);

  useEffect(() => {
    document.title = "AEGIS — Settings";
  }, []);

  // Fetch S2 /health on mount to populate the LLM Gateway readiness row.
  // Caller-owned, single-shot; per-row refresh ties into the existing test
  // action so users don't pay polling cost on Settings.
  useEffect(() => {
    let cancelled = false;
    healthCheck()
      .then((resp) => {
        if (!cancelled) setLlmGateway(resp.llmGateway ?? null);
      })
      .catch(() => {
        // Soft-fail; row falls back to Idle state
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleThemeChange = useCallback((preference: ThemePreference) => {
    setTheme(preference);
    applyTheme(preference);
  }, []);

  const handleUrlChange = useCallback((value: string) => {
    setUrl(value);
    setTestStatus("idle");
    setTestDetail("");
  }, []);

  const handleSave = useCallback(() => {
    setBackendUrl(url);
    setStoredUrl(url);
    if (theme !== storedTheme) {
      setThemePreference(theme);
      setStoredTheme(theme);
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }, [url, theme, storedTheme]);

  const handleReset = useCallback(() => {
    setBackendUrl("");
    const fresh = getBackendUrl();
    setUrl(fresh);
    setStoredUrl(fresh);
    setTestStatus("idle");
    setTestDetail("");
  }, []);

  const handleCancel = useCallback(() => {
    setUrl(storedUrl);
    setTheme(storedTheme);
    applyTheme(storedTheme);
    setTestStatus("idle");
    setTestDetail("");
  }, [storedUrl, storedTheme]);

  const handleTest = useCallback(async () => {
    setTestStatus("testing");
    setTestDetail("");
    // Generate a correlation id for this connection test so backend logs can be
    // traced back to the UI action even without an active pipeline request.
    const requestId = crypto.randomUUID();
    const { ok, data } = await healthFetch(url.trim(), requestId);
    if (ok && data) {
      setTestStatus("ok");
      setTestDetail(`${data.service ?? "backend"} ${data.version ?? ""}`.trim());
      return;
    }

    setTestStatus("error");
    setTestDetail(ok ? "비정상 응답" : "연결 실패");
  }, [url]);

  const urlDirty = useMemo(() => url !== storedUrl, [url, storedUrl]);
  const themeDirty = useMemo(() => theme !== storedTheme, [theme, storedTheme]);
  const dirty = urlDirty || themeDirty;

  return {
    url,
    saved,
    testStatus,
    testDetail,
    theme,
    urlDirty,
    themeDirty,
    dirty,
    llmGateway,
    handleUrlChange,
    handleThemeChange,
    handleSave,
    handleReset,
    handleCancel,
    handleTest,
  };
}
