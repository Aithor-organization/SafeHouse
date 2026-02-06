import { useState, useEffect, useRef, useCallback } from 'react';

const CONNECTION_TIMEOUT = 10000; // 10초 타임아웃
const MOUSE_THROTTLE_MS = 50;     // 마우스 이벤트 스로틀링 (50ms)
const SCROLL_THROTTLE_MS = 100;   // 스크롤 이벤트 스로틀링 (100ms)

// 동적 API URL 생성 (배포 환경 지원)
const getWebSocketUrl = () => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = import.meta.env.VITE_API_HOST || window.location.host;
  return `${protocol}//${host}/sandbox`;
};

const getApiUrl = (path) => {
  const host = import.meta.env.VITE_API_HOST || window.location.host;
  const protocol = window.location.protocol;
  return `${protocol}//${host}${path}`;
};

/**
 * WebSocket 기반 샌드박스 연결 훅
 * - 실시간 프레임 수신 및 Canvas 렌더링
 * - 마우스/키보드 이벤트 전송
 * - 분석 결과 수신
 * - 10초 연결 타임아웃
 */
export function useSandbox() {
  const [status, setStatus] = useState('disconnected');
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState(null);
  const [blockedDownload, setBlockedDownload] = useState(null);
  const wsRef = useRef(null);
  const canvasRef = useRef(null);
  const timeoutRef = useRef(null);
  const frameReceivedRef = useRef(false);
  const lastMouseMoveRef = useRef(0);     // 마우스 이벤트 스로틀링용
  const lastScrollRef = useRef(0);        // 스크롤 이벤트 스로틀링용
  const pendingFrameRef = useRef(null);   // requestAnimationFrame 최적화용

  // 타임아웃 클리어 함수
  const clearConnectionTimeout = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  // WebSocket 연결 및 URL 탐색 시작
  const connect = useCallback(async (url) => {
    // 기존 연결 및 타임아웃 종료
    if (wsRef.current) {
      wsRef.current.close();
    }
    clearConnectionTimeout();

    setStatus('connecting');
    setAnalysis(null);
    setError(null);
    frameReceivedRef.current = false;

    // 기존 세션 초기화 (백그라운드에서 실행, 실패해도 계속 진행)
    try {
      await fetch(getApiUrl('/reset-sessions'), { method: 'POST' });
    } catch (e) {
      console.log('세션 초기화 스킵:', e.message);
    }

    const ws = new WebSocket(getWebSocketUrl());
    wsRef.current = ws;

    // 10초 타임아웃 설정
    timeoutRef.current = setTimeout(() => {
      if (!frameReceivedRef.current) {
        setStatus('timeout');
        setError('연결 시간이 초과되었습니다. 서버 상태를 확인하거나 다시 시도해주세요.');
        if (wsRef.current) {
          wsRef.current.close();
        }
      }
    }, CONNECTION_TIMEOUT);

    ws.onopen = () => {
      setStatus('loading');
      // 샌드박스 세션 시작 요청
      ws.send(JSON.stringify({ type: 'start', url }));
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);

      switch (msg.type) {
        case 'frame':
          // 첫 프레임 수신 시 타임아웃 클리어
          if (!frameReceivedRef.current) {
            frameReceivedRef.current = true;
            clearConnectionTimeout();
            setStatus('browsing');
          }
          // Base64 인코딩된 프레임을 Canvas에 렌더링
          renderFrame(msg.data);
          break;

        case 'status':
          // 상태 업데이트 (browsing, analyzing 등)
          setStatus(msg.status);
          break;

        case 'analysis_started':
          setStatus('analyzing');
          break;

        case 'analysis_progress':
          // 분석 진행 상태 업데이트
          console.log('[분석 진행]', msg.stage, msg.message);
          break;

        case 'analysis_complete':
          // 분석 완료 - 결과 저장 (msg에서 직접 추출)
          setAnalysis({
            score: msg.riskScore,
            riskLevel: msg.riskLevel,
            summary: msg.summary,
            threats: msg.findings,
            codeAnalysis: msg.codeAnalysis,
            visualAnalysis: msg.visualAnalysis,
            recommendations: msg.recommendations,
            confidence: msg.confidence,
            // 추가 필드
            simpleExplanation: msg.simpleExplanation,
            redirectAnalysis: msg.redirectAnalysis,
            url: msg.url,
            originalUrl: msg.originalUrl,
          });
          setStatus('completed');
          break;

        case 'analysis_error':
          console.error('[분석 오류]', msg.error);
          break;

        case 'error':
          setError(msg.message);
          setStatus('error');
          break;

        case 'download_blocked':
          // 다운로드 차단 알림
          setBlockedDownload({
            filename: msg.filename,
            fileSize: msg.fileSizeFormatted,
            contentType: msg.contentType,
            riskScore: msg.riskScore,
            riskLevel: msg.riskLevel,
            threats: msg.threats || [],
            message: msg.message,
            timestamp: msg.timestamp,
          });
          break;

        default:
          console.log('Unknown message type:', msg.type);
      }
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
      setError('WebSocket 연결 오류');
      setStatus('error');
    };

    ws.onclose = () => {
      setStatus('disconnected');
    };
  }, []);

  // Base64 프레임을 Canvas에 렌더링 (requestAnimationFrame 최적화)
  const renderFrame = useCallback((base64Data) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // 이전 대기 중인 프레임 취소 (최신 프레임만 렌더링)
    if (pendingFrameRef.current) {
      cancelAnimationFrame(pendingFrameRef.current);
    }

    pendingFrameRef.current = requestAnimationFrame(() => {
      const ctx = canvas.getContext('2d');
      const img = new Image();

      img.onload = () => {
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      };

      img.src = `data:image/jpeg;base64,${base64Data}`;
      pendingFrameRef.current = null;
    });
  }, []);

  // 마우스 이동 이벤트 전송 (50ms 스로틀링으로 WebSocket 부하 감소)
  const sendMouseMove = useCallback((x, y) => {
    const now = Date.now();
    if (now - lastMouseMoveRef.current < MOUSE_THROTTLE_MS) {
      return; // 스로틀링: 50ms 내 중복 이벤트 무시
    }
    lastMouseMoveRef.current = now;

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'mousemove',
        x: Math.round(x),
        y: Math.round(y)
      }));
    }
  }, []);

  // 클릭 이벤트 전송
  const sendClick = useCallback((x, y, button = 'left') => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'click',
        x: Math.round(x),
        y: Math.round(y),
        button
      }));
    }
  }, []);

  // 키보드 이벤트 전송
  const sendKeyDown = useCallback((key) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'keydown',
        key
      }));
    }
  }, []);

  // 스크롤 이벤트 전송 (100ms 스로틀링)
  const sendScroll = useCallback((deltaX, deltaY) => {
    const now = Date.now();
    if (now - lastScrollRef.current < SCROLL_THROTTLE_MS) {
      return; // 스로틀링: 100ms 내 중복 이벤트 무시
    }
    lastScrollRef.current = now;

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'scroll',
        deltaX: Math.round(deltaX),
        deltaY: Math.round(deltaY)
      }));
    }
  }, []);

  // 뒤로가기
  const sendGoBack = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'goBack' }));
    }
  }, []);

  // 앞으로가기
  const sendGoForward = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'goForward' }));
    }
  }, []);

  // 새로고침
  const sendReload = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'reload' }));
    }
  }, []);

  // 연결 종료
  const disconnect = useCallback(() => {
    clearConnectionTimeout();
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStatus('disconnected');
    setAnalysis(null);
    setError(null);
    setBlockedDownload(null);
  }, [clearConnectionTimeout]);

  // 다운로드 알림 닫기
  const dismissDownloadAlert = useCallback(() => {
    setBlockedDownload(null);
  }, []);

  // 컴포넌트 언마운트 시 연결 및 타임아웃 종료
  useEffect(() => {
    return () => {
      clearConnectionTimeout();
      if (wsRef.current) {
        wsRef.current.close();
      }
      // 대기 중인 애니메이션 프레임 취소
      if (pendingFrameRef.current) {
        cancelAnimationFrame(pendingFrameRef.current);
      }
    };
  }, [clearConnectionTimeout]);

  return {
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
  };
}
