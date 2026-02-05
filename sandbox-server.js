/**
 * Safe-Link Sandbox WebSocket Server
 * CDP Screencast를 통한 실시간 브라우저 스트리밍
 *
 * 포트: 4000 (WebSocket /sandbox 경로)
 * 기능: 실시간 스크린캐스트, 마우스/키보드 이벤트 처리
 *
 * 변경사항 v2.0:
 * - SandboxSession 클래스 모듈화
 * - SessionManager 기반 세션 관리
 * - 동시 세션 제한 (로컬 데모용: 1개)
 * - 페이지 이동 감지 및 재분석 트리거
 */

import 'dotenv/config';
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { SandboxSession, SessionManager, validateUrl, log } from './sandbox-session.js';

// ES Module에서 __dirname 구현
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 정적 파일 경로
const STATIC_DIR = path.join(__dirname, 'frontend', 'dist');

// MIME 타입 매핑
const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
};
import { analyzeInBackground } from './live-analyzer.js';

// ============================================
// 상수 정의
// ============================================

const PORT = process.env.SANDBOX_PORT || 4000;
const MAX_CONCURRENT_SESSIONS = parseInt(process.env.MAX_SESSIONS, 10) || 1; // 로컬 데모용: 1개

// ============================================
// HTTP 서버 생성
// ============================================

const server = http.createServer(async (req, res) => {
  // CORS 헤더
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Health check 엔드포인트
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        status: 'ok',
        service: 'safe-link-sandbox-ws',
        version: '2.0.0',
        timestamp: new Date().toISOString(),
        sessions: {
          active: sessionManager.getActiveCount(),
          max: MAX_CONCURRENT_SESSIONS,
        },
      })
    );
    return;
  }

  // 세션 상태 엔드포인트
  if (req.url === '/sessions') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        sessions: sessionManager.getAllSessionInfo(),
        capacity: {
          current: sessionManager.getActiveCount(),
          max: MAX_CONCURRENT_SESSIONS,
          available: sessionManager.hasCapacity(),
        },
      })
    );
    return;
  }

  // 세션 초기화 엔드포인트
  if (req.url === '/reset-sessions' && req.method === 'POST') {
    try {
      const clearedCount = await sessionManager.clearAllSessions();
      log(`모든 세션 초기화 완료: ${clearedCount}개 세션 종료`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          success: true,
          message: `${clearedCount}개 세션이 초기화되었습니다.`,
          clearedCount,
        })
      );
    } catch (error) {
      log(`세션 초기화 오류: ${error.message}`, 'ERROR');
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          success: false,
          error: error.message,
        })
      );
    }
    return;
  }

  // ============================================
  // 정적 파일 서빙 (프론트엔드)
  // ============================================

  // URL 경로 정규화
  let filePath = req.url === '/' ? '/index.html' : req.url;

  // 쿼리 스트링 제거
  filePath = filePath.split('?')[0];

  // 전체 파일 경로
  const fullPath = path.join(STATIC_DIR, filePath);

  // 디렉토리 탈출 방지
  if (!fullPath.startsWith(STATIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  // 파일 존재 확인 및 서빙
  try {
    const stat = fs.statSync(fullPath);

    if (stat.isFile()) {
      const ext = path.extname(fullPath).toLowerCase();
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      res.writeHead(200, { 'Content-Type': contentType });
      fs.createReadStream(fullPath).pipe(res);
      return;
    }
  } catch (err) {
    // 파일이 없으면 SPA 라우팅을 위해 index.html 반환
    const indexPath = path.join(STATIC_DIR, 'index.html');

    if (fs.existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      fs.createReadStream(indexPath).pipe(res);
      return;
    }
  }

  res.writeHead(404);
  res.end('Not Found');
});

// ============================================
// WebSocket 서버 생성
// ============================================

const wss = new WebSocketServer({
  server,
  path: '/sandbox',
});

// 세션 매니저 초기화
const sessionManager = new SessionManager({
  maxSessions: MAX_CONCURRENT_SESSIONS,
});

// ============================================
// WebSocket 연결 핸들러
// ============================================

wss.on('connection', async (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  log(`WebSocket 연결 시도: ${clientIp}`);

  // 용량 확인
  if (!sessionManager.hasCapacity()) {
    log(`세션 거부: 용량 초과 (${sessionManager.getActiveCount()}/${MAX_CONCURRENT_SESSIONS})`, 'WARN');
    ws.send(
      JSON.stringify({
        type: 'status',
        state: 'error',
        message: `동시 세션 수가 초과되었습니다. (최대 ${MAX_CONCURRENT_SESSIONS}개)`,
      })
    );
    ws.close(1013, 'Session limit exceeded');
    return;
  }

  // 세션 생성
  const session = sessionManager.createSession(ws, {
    onNavigation: async (sess, url) => {
      log(`[Session ${sess.id}] 재분석 콜백 트리거: ${url}`);
      // AI 분석 실행 (원래 URL 전달)
      if (sess.page && sess.isActive) {
        try {
          await analyzeInBackground(sess.page, (msg) => sess.send(msg), {
            originalUrl: sess.originalUrl,
          });
        } catch (err) {
          log(`[Session ${sess.id}] AI 분석 오류: ${err.message}`, 'ERROR');
        }
      }
    },
    onTimeout: (sess) => {
      log(`[Session ${sess.id}] 타임아웃 콜백 트리거`);
    },
  });

  if (!session) {
    ws.send(
      JSON.stringify({
        type: 'status',
        state: 'error',
        message: '세션 생성에 실패했습니다.',
      })
    );
    ws.close(1011, 'Session creation failed');
    return;
  }

  log(`WebSocket 연결 성공: ${session.id} (${clientIp})`);
  session.sendStatus('connected', `WebSocket 연결됨 (세션 ID: ${session.id})`);

  // ============================================
  // 메시지 핸들러
  // ============================================

  ws.on('message', async (rawData) => {
    try {
      const message = JSON.parse(rawData.toString());

      switch (message.type) {
        // 세션 시작
        case 'start':
          if (message.url) {
            // 원래 URL 저장 (리다이렉트 감지용)
            session.originalUrl = message.url;
            const success = await session.initialize(message.url);
            if (success) {
              await session.startScreencast();
              // AI 분석 시작 (백그라운드, 원래 URL 전달)
              if (session.page && session.isActive) {
                analyzeInBackground(session.page, (msg) => session.send(msg), {
                  originalUrl: session.originalUrl,
                }).catch(err => log(`[Session ${session.id}] AI 분석 오류: ${err.message}`, 'ERROR'));
              }
            }
          } else {
            session.sendStatus('error', 'URL이 필요합니다.');
          }
          break;

        // 세션 중지
        case 'stop':
          await session.stop();
          break;

        // 입력 이벤트 (통합 처리)
        case 'mousemove':
        case 'click':
        case 'keydown':
        case 'keyup':
        case 'keypress':
        case 'scroll':
          await session.handleInput(message);
          break;

        // 네비게이션
        case 'goBack':
          await session.goBack();
          break;

        case 'goForward':
          await session.goForward();
          break;

        case 'reload':
          await session.reload();
          break;

        // 세션 정보 요청
        case 'info':
          session.send({
            type: 'sessionInfo',
            ...session.getInfo(),
          });
          break;

        // 스크린샷 요청
        case 'screenshot':
          const screenshot = await session.captureScreenshot();
          if (screenshot) {
            session.send({
              type: 'screenshot',
              data: screenshot,
            });
          }
          break;

        // 페이지 콘텐츠 요청
        case 'getContent':
          const content = await session.getPageContent();
          if (content) {
            session.send({
              type: 'pageContent',
              html: content,
            });
          }
          break;

        default:
          log(`[Session ${session.id}] 알 수 없는 메시지 타입: ${message.type}`, 'WARN');
      }
    } catch (error) {
      log(`[Session ${session.id}] 메시지 처리 오류: ${error.message}`, 'ERROR');
      session.sendStatus('error', '메시지 처리 실패');
    }
  });

  // ============================================
  // 연결 종료 핸들러
  // ============================================

  ws.on('close', async (code, reason) => {
    log(`WebSocket 연결 종료: ${session.id} (code: ${code}, reason: ${reason})`);
    await session.cleanup();
  });

  // ============================================
  // 에러 핸들러
  // ============================================

  ws.on('error', (error) => {
    log(`WebSocket 오류: ${session.id} - ${error.message}`, 'ERROR');
  });
});

// ============================================
// 서버 시작
// ============================================

server.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════╗');
  console.log('║   Safe-Link Sandbox WebSocket Server v2.0          ║');
  console.log('╠════════════════════════════════════════════════════╣');
  console.log(`║   Port: ${PORT}                                        ║`);
  console.log('║   Path: /sandbox                                   ║');
  console.log('║   Timeout: 5분                                     ║');
  console.log(`║   Max Sessions: ${MAX_CONCURRENT_SESSIONS}                                  ║`);
  console.log('╠════════════════════════════════════════════════════╣');
  console.log('║   Features:                                        ║');
  console.log('║     - CDP Screencast (JPEG, 80%)                   ║');
  console.log('║     - Mouse/Keyboard Events                        ║');
  console.log('║     - URL Filtering (SSRF 방지)                    ║');
  console.log('║     - Redirect Limiting (max 5)                    ║');
  console.log('║     - Page Navigation Detection                    ║');
  console.log('║     - Session Manager with Capacity Control        ║');
  console.log('╠════════════════════════════════════════════════════╣');
  console.log('║   Endpoints:                                       ║');
  console.log('║     - GET /health    - Health check                ║');
  console.log('║     - GET /sessions  - Session info                ║');
  console.log('║     - WS  /sandbox   - WebSocket endpoint          ║');
  console.log('╚════════════════════════════════════════════════════╝');
  console.log('');
});

// ============================================
// 프로세스 종료 핸들러
// ============================================

async function gracefulShutdown(signal) {
  log(`${signal} 수신, 서버 종료 시작...`, 'INFO');

  // 모든 세션 정리
  await sessionManager.cleanupAll();

  // HTTP 서버 종료
  server.close(() => {
    log('서버 종료 완료', 'INFO');
    process.exit(0);
  });

  // 강제 종료 타이머 (10초)
  setTimeout(() => {
    log('강제 종료', 'WARN');
    process.exit(1);
  }, 10000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// ============================================
// Export
// ============================================

export { sessionManager, server, wss };
