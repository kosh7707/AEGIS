import "./MonitoringView.css";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { AttackScenario, CanInjectionResponse, CanMessage, DynamicAlert, DynamicAnalysisSession, InjectionClassification, WsMessage as SharedWsMessage } from "@aegis/shared";
import { AlertTriangle, Pause, Play, Plug, Radio, Send, Square, Wifi, WifiOff } from "lucide-react";
import { cn } from "@/common/utils/cn";
import { fetchDynamicSessionDetail, fetchInjections, fetchScenarios, getWsBaseUrl, injectCanMessage, injectScenario, logError, stopDynamicSession } from "@/common/api/client";
import { useToast } from "@/common/contexts/ToastContext";
import { BackButton, ConnectionStatusBanner, SeverityBadge, Spinner } from "@/common/ui/primitives";
import { formatTime } from "@/common/utils/format";
import { createReconnectingWs, createSeqTracker, parseWsMessage, type ConnectionState } from "@/common/utils/wsEnvelope";

const MAX_MESSAGES = 500;

const injectionBadgeClass: Record<InjectionClassification, string> = {
  normal: "monitoring-injection-badge monitoring-injection-badge--normal",
  crash: "monitoring-injection-badge monitoring-injection-badge--crash",
  anomaly: "monitoring-injection-badge monitoring-injection-badge--anomaly",
  timeout: "monitoring-injection-badge monitoring-injection-badge--timeout",
};

const tableHeadClass = "monitoring-table-head";
const cellMonoClass = "monitoring-cell-data";

type PanelTab = "alerts" | "inject" | "history";

interface Props {
  session: DynamicAnalysisSession;
  onBack: () => void;
  onStopped: () => void;
}

export const MonitoringView: React.FC<Props> = ({ session, onBack, onStopped }) => {
  const [messages, setMessages] = useState<CanMessage[]>([]);
  const [alerts, setAlerts] = useState<DynamicAlert[]>([]);
  const [messageCount, setMessageCount] = useState(0);
  const [alertCount, setAlertCount] = useState(0);
  const [wsConnected, setWsConnected] = useState(false);
  const [wsConnectionState, setWsConnectionState] = useState<ConnectionState>("disconnected");
  const [stopping, setStopping] = useState(false);
  const [paused, setPaused] = useState(false);
  const pausedRef = useRef(false);
  const bufferRef = useRef<CanMessage[]>([]);
  const [activeTab, setActiveTab] = useState<PanelTab>("alerts");
  const [scenarios, setScenarios] = useState<AttackScenario[]>([]);
  const [injections, setInjections] = useState<CanInjectionResponse[]>([]);
  const [injForm, setInjForm] = useState({ canId: "", dlc: 8, data: "", label: "" });
  const [injecting, setInjecting] = useState(false);
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [injError, setInjError] = useState<string | null>(null);
  const toast = useToast();
  const wsRef = useRef<WebSocket | null>(null);
  const canWrapperRef = useRef<HTMLDivElement>(null);

  const hasData = messages.length > 0 || messageCount > 0;

  useEffect(() => {
    const wsUrl = `${getWsBaseUrl()}/ws/dynamic-analysis?sessionId=${session.id}`;
    const seqTracker = createSeqTracker("dynamic-analysis");

    function wireHandlers(ws: WebSocket | null) {
      if (!ws) return;
      ws.onmessage = (event) => {
        try {
          const parsed = parseWsMessage(event.data);
          seqTracker.check(parsed.meta);
          const msg = parsed as unknown as SharedWsMessage;
          switch (msg.type) {
            case "message":
              if (pausedRef.current) {
                const bufferedMessages = bufferRef.current;
                bufferedMessages.push(msg.payload);
                if (bufferedMessages.length > MAX_MESSAGES) bufferRef.current = bufferedMessages.slice(-MAX_MESSAGES);
              } else {
                setMessages((previous) => {
                  const next = [...previous, msg.payload];
                  return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next;
                });
              }
              break;
            case "alert":
              setAlerts((previous) => [msg.payload, ...previous]);
              break;
            case "status":
              setMessageCount(msg.payload.messageCount);
              setAlertCount(msg.payload.alertCount);
              break;
            case "injection-result":
              setInjections((previous) => [msg.payload, ...previous]);
              break;
            case "injection-error":
              setInjError(msg.payload.error);
              break;
          }
        } catch (error) {
          console.warn("[WS:dynamic-analysis] malformed message:", error);
        }
      };
    }

    const reconnectingWs = createReconnectingWs(() => wsUrl, {
      maxRetries: 10,
      onStateChange(state: ConnectionState) {
        setWsConnected(state === "connected");
        setWsConnectionState(state);
      },
      onDisconnect() {
        seqTracker.reset();
      },
      async onReconnect() {
        try {
          const detail = await fetchDynamicSessionDetail(session.id);
          setAlerts(detail.alerts);
          setMessages((previous) => {
            const combined = [...previous, ...detail.recentMessages];
            const seen = new Set<string>();
            const deduped = combined.filter((m) => {
              const key = `${m.timestamp}:${m.id}:${m.data}`;
              if (seen.has(key)) return false;
              seen.add(key);
              return true;
            });
            return deduped.length > MAX_MESSAGES ? deduped.slice(-MAX_MESSAGES) : deduped;
          });
          if (detail.session.status) {
            setMessageCount((previous) => Math.max(previous, detail.recentMessages.length));
            setAlertCount((previous) => Math.max(previous, detail.alerts.length));
          }
        } catch (error) {
          console.warn("[WS:dynamic-analysis] REST recovery failed:", error);
        }
        wireHandlers(reconnectingWs.getWs());
      },
      // onGiveUp: setState("failed") is called by createReconnectingWs before
      // invoking onGiveUp, so onStateChange already surfaces the "failed" state.
    });

    wireHandlers(reconnectingWs.getWs());
    wsRef.current = reconnectingWs.getWs();
    return () => {
      reconnectingWs.close();
      wsRef.current = null;
    };
  }, [session.id]);

  useEffect(() => {
    fetchScenarios().then(setScenarios).catch((error) => logError("Load scenarios", error));
    fetchInjections(session.id).then((data) => setInjections([...data].reverse())).catch((error) => logError("Load injections", error));
  }, [session.id]);

  useEffect(() => {
    pausedRef.current = paused;
    if (!paused && bufferRef.current.length > 0) {
      const buffered = bufferRef.current;
      bufferRef.current = [];
      setMessages((previous) => {
        const next = [...previous, ...buffered];
        return next.length > MAX_MESSAGES ? next.slice(-MAX_MESSAGES) : next;
      });
    }
  }, [paused]);

  useEffect(() => {
    if (!paused && canWrapperRef.current) {
      canWrapperRef.current.scrollTop = canWrapperRef.current.scrollHeight;
    }
  }, [messages, paused]);

  const flaggedMessages = useMemo(() => messages.filter((message) => message.flagged), [messages]);

  const handleStop = useCallback(async () => {
    setStopping(true);
    try {
      wsRef.current?.close();
      await stopDynamicSession(session.id);
      onStopped();
    } catch (error) {
      logError("Stop session", error);
      toast.error("세션 종료에 실패했습니다.");
      setStopping(false);
    }
  }, [onStopped, session.id, toast]);

  const handleInject = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!injForm.canId || !injForm.data) return;
    setInjecting(true);
    setInjError(null);
    try {
      const result = await injectCanMessage(session.id, { canId: injForm.canId.trim(), dlc: injForm.dlc, data: injForm.data.trim(), label: injForm.label.trim() || undefined });
      setInjections((previous) => [result, ...previous]);
    } catch (error) {
      setInjError(error instanceof Error ? error.message : "주입 실패");
    } finally {
      setInjecting(false);
    }
  };

  const handleRunScenario = async (scenarioId: string) => {
    setRunningScenario(scenarioId);
    setInjError(null);
    try {
      const results = await injectScenario(session.id, scenarioId);
      setInjections((previous) => [...[...results].reverse(), ...previous]);
    } catch (error) {
      setInjError(error instanceof Error ? error.message : "시나리오 실행 실패");
    } finally {
      setRunningScenario(null);
    }
  };

  return (
    <div className="monitoring-shell">
      <ConnectionStatusBanner connectionState={wsConnectionState} />
      <BackButton onClick={onBack} label="세션 목록으로" />

      <div className="panel monitoring-status-card">
        <div className="panel-body">
          <div className="monitoring-status-row">
            <div className="monitoring-status-badges">
              <span
                className={cn(
                  "monitoring-connection-badge",
                  wsConnected
                    ? "monitoring-connection-badge--connected"
                    : "monitoring-connection-badge--disconnected",
                )}
              >
                {wsConnected ? <Wifi size={14} /> : <WifiOff size={14} />}
                {wsConnected ? "연결됨" : "연결 끊김"}
              </span>
              <span className="monitoring-status-badge"><Plug size={12} />{session.source.adapterName ?? "어댑터"}</span>
              <span className="monitoring-status-badge"><Radio size={12} /> 메시지 {messageCount || messages.length}</span>
              <span className="monitoring-status-badge"><AlertTriangle size={12} /> 알림 {alertCount || alerts.length}</span>
            </div>
            <button type="button" className="btn btn-danger monitoring-stop" onClick={handleStop} disabled={stopping}>{stopping ? <Spinner size={14} /> : <Square size={14} />}세션 종료</button>
          </div>
        </div>
      </div>

      {!hasData ? (
        <div className="panel monitoring-empty-card">
          <div className="panel-body">
            <div className="monitoring-empty-icon"><Plug size={32} /></div>
            <div className="monitoring-empty-copy">
              <h3 className="monitoring-empty-title">어댑터에서 데이터 대기 중...</h3>
              <p className="monitoring-empty-body">ECU 시뮬레이터 또는 실 ECU가 어댑터에 연결되면 CAN 데이터 수신이 시작됩니다.<br />또는 아래 <strong>CAN 주입</strong> 탭에서 직접 메시지를 전송할 수 있습니다.</p>
            </div>
          </div>
        </div>
      ) : null}

      <div className="monitoring-grid">
        <div className="monitoring-left">
          <div className="panel">
            <div className="panel-head monitoring-card-head">
              <div>
                <h3 className="panel-title">CAN 메시지</h3>
                <p className="panel-description">최근 {Math.min(messages.length, MAX_MESSAGES)}개의 메시지를 실시간으로 표시합니다.</p>
              </div>
              <button className={cn("btn btn-outline btn-sm", "monitoring-toggle", paused && "is-paused")} type="button" onClick={() => setPaused((previous) => !previous)}>
                {paused ? <Play size={12} /> : <Pause size={12} />}
                {paused ? "재개" : "일시정지"}
              </button>
            </div>
            <div className="panel-body">
              <div ref={canWrapperRef} className="monitoring-stream-wrap">
                <table className="data-table">
                  <thead className={tableHeadClass}>
                    <tr>
                      <th className={tableHeadClass}>시간</th>
                      <th className={tableHeadClass}>CAN ID</th>
                      <th className="monitoring-table-head monitoring-table-head--center">DLC</th>
                      <th className={tableHeadClass}>데이터</th>
                    </tr>
                  </thead>
                  <tbody>
                    {messages.length === 0 ? (
                      <tr><td colSpan={4} className="monitoring-waiting">CAN 메시지 대기 중...</td></tr>
                    ) : messages.map((message, index) => (
                      <tr key={index} className={cn(message.flagged && "monitoring-row-flagged", message.injected && !message.flagged && "monitoring-row-injected")}>
                        <td className="monitoring-cell-time">{formatTime(message.timestamp)}</td>
                        <td className="monitoring-cell-id">
                          <div className="monitoring-cell-id-wrap">
                            {message.injected ? <span className="monitoring-cell-injected-badge">INJ</span> : null}
                            <span>{message.id}</span>
                          </div>
                        </td>
                        <td className="monitoring-cell-center">{message.dlc}</td>
                        <td className={cellMonoClass}>{message.data}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {flaggedMessages.length > 0 ? (
            <div className="panel">
              <div className="panel-head">
                <h3 className="panel-title monitoring-flagged-title"><AlertTriangle size={14} /> 알림 패킷 ({flaggedMessages.length})</h3>
                <p className="panel-description">탐지 규칙에 의해 표시된 패킷만 별도로 모아 보여줍니다.</p>
              </div>
              <div className="panel-body">
                <div className="scroll-area monitoring-side-scroll-flagged">
                  <table className="data-table">
                    <thead className={tableHeadClass}>
                      <tr>
                        <th className={tableHeadClass}>시간</th>
                        <th className={tableHeadClass}>CAN ID</th>
                        <th className="monitoring-table-head monitoring-table-head--center">DLC</th>
                        <th className={tableHeadClass}>데이터</th>
                      </tr>
                    </thead>
                    <tbody>
                      {flaggedMessages.map((message, index) => (
                        <tr key={index} className="monitoring-row-flagged">
                          <td className="monitoring-cell-time">{formatTime(message.timestamp)}</td>
                          <td className="monitoring-cell-id monitoring-cell-id--flagged">{message.id}</td>
                          <td className="monitoring-cell-center">{message.dlc}</td>
                          <td className={cellMonoClass}>{message.data}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : null}
        </div>

        <div className="panel monitoring-side-card">
          <div className="panel-body">
            <div value={activeTab} onValueChange={(value) => setActiveTab(value as PanelTab)} className="monitoring-tabs-shell">
              <div className="seg monitoring-tabs" role="tablist">
                <button type="button" role="tab" value="alerts" className="btn btn-primary monitoring-tab">알림{alerts.length > 0 ? <span className="monitoring-tab-badge">{alerts.length}</span> : null}</button>
                <button type="button" role="tab" value="inject" className="btn btn-primary btn-sm monitoring-tab">CAN 주입</button>
                <button type="button" role="tab" value="history" className="monitoring-tab">주입 이력{injections.length > 0 ? <span className="monitoring-tab-badge">{injections.length}</span> : null}</button>
              </div>

              <div role="tabpanel" value="alerts" className="monitoring-tab-panel">
                {alerts.length === 0 ? (
                  <div className="monitoring-tab-empty">아직 탐지된 이상이 없습니다</div>
                ) : (
                  <div className="scroll-area monitoring-side-scroll-alerts">
                    <div className="monitoring-alert-list">
                      {alerts.map((alert) => (
                        <div className="panel panel-alert monitoring-alert" key={alert.id}>
                          <AlertTriangle size={16} className="monitoring-alert-icon" />
                          <div className="monitoring-alert-body">
                            <div>
                              <div className="monitoring-alert-head">
                                <SeverityBadge severity={alert.severity} />
                                <strong className="alert-title">{alert.title}</strong>
                              </div>
                              <span className="alert-description">{alert.description}</span>
                            </div>
                            {alert.llmAnalysis ? <div className="monitoring-alert-llm"><span className="monitoring-llm-badge">LLM</span><p className="finding-body-text">{alert.llmAnalysis}</p></div> : null}
                            <div className="monitoring-alert-time">{formatTime(alert.detectedAt)}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div role="tabpanel" value="inject" className="monitoring-tab-panel">
                <form onSubmit={handleInject} className="monitoring-inject-form">
                  <div className="monitoring-inject-grid">
                    <label className="form-label monitoring-field"><span className="monitoring-field-label">CAN ID</span><input className="form-input" value={injForm.canId} onChange={(event) => setInjForm((previous) => ({ ...previous, canId: event.target.value }))} placeholder="0x7DF" /></label>
                    <label className="form-label monitoring-field"><span className="monitoring-field-label">DLC</span><input className="form-input" type="number" min={0} max={8} value={injForm.dlc} onChange={(event) => setInjForm((previous) => ({ ...previous, dlc: Number(event.target.value) }))} /></label>
                  </div>
                  <label className="form-label monitoring-field"><span className="monitoring-field-label">Data</span><input className="form-input monitoring-field-mono" value={injForm.data} onChange={(event) => setInjForm((previous) => ({ ...previous, data: event.target.value }))} placeholder="FF FF FF FF FF FF FF FF" /></label>
                  <label className="form-label monitoring-field"><span className="monitoring-field-label">Label (선택)</span><input className="form-input" value={injForm.label} onChange={(event) => setInjForm((previous) => ({ ...previous, label: event.target.value }))} placeholder="Diagnostic Request" /></label>
                  <button  type="submit" disabled={injecting || !injForm.canId.trim() || !injForm.data.trim() || stopping}>{injecting ? <Spinner size={14} /> : <Send size={14} />}주입</button>
                </form>

                {injError ? <div className="panel panel-alert"><AlertTriangle size={16} /><strong className="alert-title">주입 요청 실패</strong><span className="alert-description">{injError}</span></div> : null}

                <div className="monitoring-scenario-list">
                  <div>
                    <div className="dynamic-test-section-title">공격 시나리오</div>
                    <p className="dynamic-test-option-desc">준비된 시나리오를 실행해 ECU 응답을 비교합니다.</p>
                  </div>
                  <div className="scroll-area monitoring-side-scroll-scenarios">
                    <div className="monitoring-scenario-list">
                      {scenarios.length === 0 ? (
                        <div className="monitoring-tab-empty">로딩 중...</div>
                      ) : scenarios.map((scenario) => (
                        <div className="panel monitoring-scenario-card" key={scenario.id}>
                          <div className="panel-body">
                            <div className="monitoring-scenario-head">
                              <div className="monitoring-scenario-copy">
                                <div className="monitoring-scenario-title"><SeverityBadge severity={scenario.severity} /> <span>{scenario.name}</span></div>
                                <p className="monitoring-scenario-desc">{scenario.description}</p>
                              </div>
                              <span>{scenario.steps.length}단계</span>
                            </div>
                            <div className="monitoring-scenario-actions"><button type="button" disabled={runningScenario !== null || stopping} onClick={() => handleRunScenario(scenario.id)}>{runningScenario === scenario.id ? <Spinner size={12} /> : <Play size={12} />}실행</button></div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div role="tabpanel" value="history" className="monitoring-tab-panel">
                {injections.length === 0 ? (
                  <div className="monitoring-tab-empty">아직 주입 이력이 없습니다</div>
                ) : (
                  <div className="scroll-area monitoring-side-scroll-history">
                    <div className="monitoring-injection-list">
                      {injections.map((injection) => (
                        <div className="panel monitoring-injection-card" key={injection.id}>
                          <div className="panel-body">
                            <div className="monitoring-injection-head">
                              <span className={injectionBadgeClass[injection.classification]}>{injection.classification}</span>
                              <code className="monitoring-injection-code">{injection.request.canId}</code>
                              {injection.request.label ? <span>{injection.request.label}</span> : null}
                            </div>
                            <div className="monitoring-injection-copy">
                              <div>TX: <code>{injection.request.data}</code></div>
                              {injection.ecuResponse.data ? <div>RX: <code>{injection.ecuResponse.data}</code></div> : null}
                              {injection.ecuResponse.delayMs != null ? <div className="monitoring-injection-delay">응답 지연 {injection.ecuResponse.delayMs}ms</div> : null}
                            </div>
                            {injection.ecuResponse.error ? <div className="panel panel-alert"><AlertTriangle size={16} /><strong className="alert-title">ECU 응답 오류</strong><span className="alert-description">{injection.ecuResponse.error}</span></div> : null}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
