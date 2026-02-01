/**
 * Safe-Link Sandbox API Server
 * URL 안전성 분석 샌드박스 서비스
 *
 * 포트: 4000
 * 주요 기능: URL 분석, 샌드박스 실행, 위험도 계산
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { analyzeUrl, quickCheck } from './analyzer.js';

const app = express();
const PORT = process.env.PORT || 4000;
const ANALYSIS_TIMEOUT = 30000; // 30초

// ============================================
// 미들웨어 설정
// ============================================

// 보안 헤더
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], // Base64 이미지 허용
    },
  },
}));

// CORS 설정
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// JSON 파싱
app.use(express.json({ limit: '1mb' }));

// 요청 로깅
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
});

// Rate Limiting (분당 30회)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1분
  max: 30,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: '요청 한도를 초과했습니다. 잠시 후 다시 시도해주세요.',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// ============================================
// API 라우트
// ============================================

/**
 * 헬스체크 엔드포인트
 * GET /health
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'safe-link-sandbox',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

/**
 * API 정보
 * GET /api
 */
app.get('/api', (req, res) => {
  res.json({
    name: 'Safe-Link Sandbox API',
    version: '1.0.0',
    endpoints: {
      'POST /api/analyze': 'URL 전체 분석 (Puppeteer 샌드박스)',
      'POST /api/quick-check': 'URL 빠른 검사 (도메인 분석만)',
      'GET /api/status': '서버 상태 확인',
    },
    riskLevels: {
      safe: '0-30점: 안전',
      warning: '31-70점: 주의 필요',
      danger: '71-100점: 위험',
    },
  });
});

/**
 * 서버 상태
 * GET /api/status
 */
app.get('/api/status', (req, res) => {
  res.json({
    success: true,
    data: {
      status: 'running',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString(),
    },
  });
});

/**
 * URL 전체 분석 (Puppeteer 샌드박스)
 * POST /api/analyze
 *
 * Request Body:
 * {
 *   "url": "https://example.com",
 *   "options": {
 *     "timeout": 30000,
 *     "takeScreenshot": true
 *   }
 * }
 *
 * Response:
 * {
 *   "success": true,
 *   "data": {
 *     "url": "https://example.com",
 *     "riskScore": 25,
 *     "riskLevel": "safe",
 *     "screenshot": "base64...",
 *     "details": {...},
 *     "analysisTime": 3500
 *   }
 * }
 */
app.post('/api/analyze', async (req, res) => {
  const { url, options = {} } = req.body;

  // 입력 검증
  if (!url) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_URL',
        message: 'URL이 필요합니다.',
      },
    });
  }

  if (typeof url !== 'string') {
    return res.status(400).json({
      success: false,
      error: {
        code: 'INVALID_URL_TYPE',
        message: 'URL은 문자열이어야 합니다.',
      },
    });
  }

  // URL 길이 제한
  if (url.length > 2048) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'URL_TOO_LONG',
        message: 'URL은 2048자를 초과할 수 없습니다.',
      },
    });
  }

  // 타임아웃 설정 (최대 30초)
  const timeout = Math.min(options.timeout || ANALYSIS_TIMEOUT, ANALYSIS_TIMEOUT);

  try {
    console.log(`[분석 시작] ${url}`);

    const result = await analyzeUrl(url, {
      timeout,
      takeScreenshot: options.takeScreenshot !== false,
    });

    console.log(`[분석 완료] ${url} - 위험도: ${result.riskScore} (${result.riskLevel})`);

    res.json({
      success: true,
      data: result,
    });

  } catch (error) {
    console.error(`[분석 오류] ${url}: ${error.message}`);

    // 오류 유형별 응답
    if (error.message.includes('유효하지 않은 URL')) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_URL',
          message: error.message,
        },
      });
    }

    if (error.message.includes('timeout') || error.message.includes('Timeout')) {
      return res.status(504).json({
        success: false,
        error: {
          code: 'ANALYSIS_TIMEOUT',
          message: '분석 시간이 초과되었습니다.',
          timeout: `${timeout}ms`,
        },
      });
    }

    res.status(500).json({
      success: false,
      error: {
        code: 'ANALYSIS_ERROR',
        message: '분석 중 오류가 발생했습니다.',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
    });
  }
});

/**
 * URL 빠른 검사 (도메인 분석만, 브라우저 미사용)
 * POST /api/quick-check
 *
 * Request Body:
 * {
 *   "url": "https://example.com"
 * }
 *
 * Response:
 * {
 *   "success": true,
 *   "data": {
 *     "url": "https://example.com",
 *     "valid": true,
 *     "riskScore": 15,
 *     "riskLevel": "safe",
 *     "issues": [],
 *     "message": "도메인 분석 통과"
 *   }
 * }
 */
app.post('/api/quick-check', (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_URL',
        message: 'URL이 필요합니다.',
      },
    });
  }

  if (typeof url !== 'string') {
    return res.status(400).json({
      success: false,
      error: {
        code: 'INVALID_URL_TYPE',
        message: 'URL은 문자열이어야 합니다.',
      },
    });
  }

  try {
    const result = quickCheck(url);

    res.json({
      success: true,
      data: result,
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'CHECK_ERROR',
        message: '검사 중 오류가 발생했습니다.',
      },
    });
  }
});

/**
 * 배치 분석 (여러 URL 동시 검사)
 * POST /api/batch-check
 *
 * Request Body:
 * {
 *   "urls": ["https://example1.com", "https://example2.com"]
 * }
 */
app.post('/api/batch-check', async (req, res) => {
  const { urls } = req.body;

  if (!urls || !Array.isArray(urls)) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_URLS',
        message: 'URL 배열이 필요합니다.',
      },
    });
  }

  // 최대 10개 URL 제한
  if (urls.length > 10) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'TOO_MANY_URLS',
        message: '한 번에 최대 10개의 URL만 검사할 수 있습니다.',
      },
    });
  }

  try {
    const results = urls.map(url => quickCheck(url));

    res.json({
      success: true,
      data: {
        total: urls.length,
        results,
        summary: {
          safe: results.filter(r => r.riskLevel === 'safe').length,
          warning: results.filter(r => r.riskLevel === 'warning').length,
          danger: results.filter(r => r.riskLevel === 'danger').length,
          invalid: results.filter(r => !r.valid).length,
        },
      },
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'BATCH_CHECK_ERROR',
        message: '배치 검사 중 오류가 발생했습니다.',
      },
    });
  }
});

// ============================================
// 에러 핸들링
// ============================================

// 404 처리
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: '요청한 엔드포인트를 찾을 수 없습니다.',
      path: req.path,
    },
  });
});

// 전역 에러 핸들러
app.use((err, req, res, next) => {
  console.error(`[서버 오류] ${err.message}`);
  console.error(err.stack);

  res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: '서버 내부 오류가 발생했습니다.',
    },
  });
});

// ============================================
// 서버 시작
// ============================================

app.listen(PORT, () => {
  console.log('╔════════════════════════════════════════════╗');
  console.log('║     Safe-Link Sandbox API Server v1.0.0    ║');
  console.log('╠════════════════════════════════════════════╣');
  console.log(`║  Port: ${PORT}                                 ║`);
  console.log(`║  Timeout: ${ANALYSIS_TIMEOUT}ms                        ║`);
  console.log('║  Endpoints:                                ║');
  console.log('║    POST /api/analyze      - 전체 분석      ║');
  console.log('║    POST /api/quick-check  - 빠른 검사      ║');
  console.log('║    POST /api/batch-check  - 배치 검사      ║');
  console.log('║    GET  /health           - 헬스체크       ║');
  console.log('╚════════════════════════════════════════════╝');
});

export default app;
