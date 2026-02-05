import { useState, useRef } from 'react';
import { useSandbox } from './hooks/useSandbox';
import { UrlInput } from './components/UrlInput';
import { SandboxViewer } from './components/SandboxViewer';
import { RiskPanel } from './components/RiskPanel';
import './App.css';

// 동적 API URL 생성 (배포 환경 지원)
const getApiUrl = (path) => {
  const host = import.meta.env.VITE_API_HOST || window.location.host;
  const protocol = window.location.protocol;
  return `${protocol}//${host}${path}`;
};

/**
 * Safe-Link Sandbox 메인 앱
 * 레이아웃: URL 입력 → 요약 바 → 샌드박스 → 상세 분석
 */
function App() {
  const {
    status,
    analysis,
    error,
    blockedDownload,
    canvasRef,
    connect,
    disconnect,
    dismissDownloadAlert,
    sendMouseMove,
    sendClick,
    sendKeyDown,
    sendScroll,
    sendGoBack,
    sendGoForward,
    sendReload
  } = useSandbox();

  const detailRef = useRef(null);
  const [showDetail, setShowDetail] = useState(false);
  const [resetting, setResetting] = useState(false);

  // 세션 초기화
  const resetSessions = async () => {
    if (resetting) return;
    setResetting(true);
    try {
      const res = await fetch(getApiUrl('/reset-sessions'), { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        alert(`✅ ${data.message}`);
        window.location.reload();
      } else {
        alert(`❌ 초기화 실패: ${data.error}`);
      }
    } catch (err) {
      alert(`❌ 서버 연결 오류: ${err.message}`);
    } finally {
      setResetting(false);
    }
  };

  // 상세 보기 클릭 시 스크롤
  const scrollToDetail = () => {
    setShowDetail(true);
    setTimeout(() => {
      detailRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  // 상태별 메시지
  const getStatusInfo = () => {
    switch (status) {
      case 'disconnected':
        return { text: '대기 중', color: '#888', icon: '⏸️' };
      case 'connecting':
        return { text: '연결 중...', color: '#FFC107', icon: '🔄' };
      case 'connected':
        return { text: '연결됨', color: '#4CAF50', icon: '🟢' };
      case 'browsing':
        return { text: '브라우징 중...', color: '#2196F3', icon: '🌐' };
      case 'analyzing':
        return { text: 'AI 분석 중...', color: '#9C27B0', icon: '🔄' };
      case 'completed':
        return { text: '분석 완료', color: '#4CAF50', icon: '✅' };
      case 'error':
        return { text: '오류 발생', color: '#F44336', icon: '❌' };
      default:
        return { text: status, color: '#888', icon: '⏸️' };
    }
  };

  // 요약 바 데이터
  const getSummaryData = () => {
    if (status === 'analyzing') {
      return { type: 'loading', text: 'AI가 페이지를 분석하고 있습니다...' };
    }

    if (analysis) {
      const level = analysis.riskLevel || 'safe';
      const score = analysis.score || 0;
      const summary = analysis.summary || '분석이 완료되었습니다.';

      return {
        type: 'complete',
        level,
        score,
        text: summary.length > 60 ? summary.substring(0, 60) + '...' : summary
      };
    }

    return null;
  };

  // RiskPanel용 분석 데이터 변환
  const getRiskPanelData = () => {
    if (!analysis) return null;

    return {
      status: 'complete',
      riskScore: analysis.score || 0,
      riskLevel: analysis.riskLevel || 'safe',
      summary: analysis.summary || '',
      findings: analysis.threats?.map(t => ({
        category: t.category || t.type || '기타',
        severity: t.severity || 'medium',
        description: t.description
      })) || [],
      codeAnalysis: analysis.codeAnalysis || {
        hiddenFields: 0,
        externalScripts: 0,
        suspiciousPatterns: []
      },
      recommendations: analysis.recommendations || [],
      confidence: analysis.confidence || 85,
      // 추가 필드
      simpleExplanation: analysis.simpleExplanation || '',
      redirectAnalysis: analysis.redirectAnalysis || null,
      url: analysis.url || '',
      originalUrl: analysis.originalUrl || '',
    };
  };

  const statusInfo = getStatusInfo();
  const summaryData = getSummaryData();
  const riskPanelData = getRiskPanelData();
  const isActive = status !== 'disconnected' && status !== 'error';

  return (
    <div className="app">
      <header className="app-header">
        <h1>🔒 Safe-Link Sandbox</h1>
        <p className="subtitle">의심스러운 링크를 안전하게 검사하세요</p>
      </header>

      <main className="app-main">
        {/* URL 입력 + 네비게이션 */}
        <section className="control-section">
          <div className="url-row">
            <UrlInput
              onSubmit={connect}
              disabled={status === 'connecting' || status === 'browsing'}
            />
          </div>

          <div className="nav-row">
            <div className="nav-buttons">
              <button
                className="nav-btn"
                onClick={sendGoBack}
                disabled={!isActive}
                title="뒤로가기"
              >
                ←
              </button>
              <button
                className="nav-btn"
                onClick={sendGoForward}
                disabled={!isActive}
                title="앞으로가기"
              >
                →
              </button>
              <button
                className="nav-btn"
                onClick={sendReload}
                disabled={!isActive}
                title="새로고침"
              >
                🔄
              </button>
            </div>

            <div className="status-info">
              <span
                className="status-dot"
                style={{ backgroundColor: statusInfo.color }}
              />
              <span className="status-text">{statusInfo.text}</span>
            </div>

            {isActive && (
              <button className="disconnect-btn" onClick={disconnect}>
                세션 종료
              </button>
            )}

            {!isActive && (
              <button
                className="reset-btn"
                onClick={resetSessions}
                disabled={resetting}
                title="서버의 모든 세션을 강제 종료합니다"
              >
                {resetting ? '초기화 중...' : '🔄 세션 초기화'}
              </button>
            )}
          </div>
        </section>

        {/* 상단 로딩 바 (연결 중~프레임 수신 전) */}
        {(status === 'connecting' || status === 'connected' || status === 'loading') && (
          <div className="top-loading-bar">
            <div className="top-loading-progress"></div>
            <span className="top-loading-text">
              {status === 'connecting' && '서버에 연결 중...'}
              {status === 'connected' && '브라우저 준비 중...'}
              {status === 'loading' && '페이지 불러오는 중...'}
            </span>
          </div>
        )}

        {/* 에러 배너 */}
        {error && (
          <div className="error-banner">
            <span>❌ {error}</span>
            <button onClick={disconnect}>닫기</button>
          </div>
        )}

        {/* 다운로드 차단 알림 */}
        {blockedDownload && (
          <div className={`download-blocked-banner download-${blockedDownload.riskLevel}`}>
            <div className="download-blocked-header">
              <span className="download-blocked-icon">🚫</span>
              <span className="download-blocked-title">다운로드 차단됨</span>
              <button className="download-blocked-close" onClick={dismissDownloadAlert}>✕</button>
            </div>
            <div className="download-blocked-content">
              <div className="download-file-info">
                <div className="download-filename">{blockedDownload.filename}</div>
                <div className="download-meta">
                  <span>크기: {blockedDownload.fileSize}</span>
                  <span>타입: {blockedDownload.contentType}</span>
                </div>
              </div>
              <div className="download-risk">
                <span className="download-risk-score">
                  {blockedDownload.riskLevel === 'danger' && '🚨'}
                  {blockedDownload.riskLevel === 'warning' && '⚠️'}
                  {blockedDownload.riskLevel === 'safe' && '⚡'}
                  {' '}위험도 {blockedDownload.riskScore}점
                </span>
              </div>
              {blockedDownload.threats && blockedDownload.threats.length > 0 && (
                <ul className="download-threats">
                  {blockedDownload.threats.map((threat, idx) => (
                    <li key={idx} className={`threat-${threat.severity}`}>
                      <strong>{threat.type}:</strong> {threat.description}
                    </li>
                  ))}
                </ul>
              )}
              <div className="download-message">{blockedDownload.message}</div>
            </div>
          </div>
        )}

        {/* 요약 바 (샌드박스 위) */}
        {summaryData && (
          <section className="summary-bar-section">
            <div className={`summary-bar summary-${summaryData.type === 'loading' ? 'loading' : summaryData.level}`}>
              {summaryData.type === 'loading' ? (
                <div className="summary-loading">
                  <span className="loading-spinner-small"></span>
                  <span>{summaryData.text}</span>
                </div>
              ) : (
                <div className="summary-content">
                  <span className="summary-score">
                    {summaryData.level === 'safe' && '✅'}
                    {summaryData.level === 'warning' && '⚠️'}
                    {summaryData.level === 'danger' && '🚨'}
                    {' '}위험도 {summaryData.score}점
                  </span>
                  <span className="summary-text">{summaryData.text}</span>
                  <button className="detail-btn" onClick={scrollToDetail}>
                    ▼ 상세
                  </button>
                </div>
              )}
            </div>
          </section>
        )}

        {/* 샌드박스 뷰어 */}
        <section className="viewer-section">
          <SandboxViewer
            canvasRef={canvasRef}
            onMouseMove={sendMouseMove}
            onClick={sendClick}
            onScroll={sendScroll}
            onKeyDown={sendKeyDown}
            disabled={!isActive}
            status={status}
          />
        </section>

        {/* 상세 분석 결과 (하단) */}
        {showDetail && riskPanelData && (
          <section className="detail-section" ref={detailRef}>
            <RiskPanel analysis={riskPanelData} />
          </section>
        )}
      </main>

      <footer className="app-footer">
        <p>Safe-Link Sandbox - 링크 안전 검사 도구</p>
      </footer>
    </div>
  );
}

export default App;
