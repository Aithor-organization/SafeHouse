/**
 * Safe-Link Sandbox Analyzer
 * Puppeteer 기반 URL 샌드박스 분석 모듈
 * + AI 기반 분석 (OpenRouter Gemini 3 Flash)
 */

import puppeteer from 'puppeteer';
import { analyzeWithAI, mergeAnalysisResults } from './ai-analyzer.js';

// 위험도 판정 기준
const RISK_THRESHOLDS = {
  SAFE: 30,      // 0-30: 안전
  WARNING: 70,   // 31-70: 주의
  // 71-100: 위험
};

// 알려진 피싱 패턴
const PHISHING_PATTERNS = [
  /login.*verify/i,
  /account.*suspend/i,
  /urgent.*action/i,
  /password.*expire/i,
  /verify.*identity/i,
  /security.*alert/i,
  /confirm.*bank/i,
  /update.*payment/i,
];

// 악성 스크립트 패턴
const MALICIOUS_SCRIPT_PATTERNS = [
  /eval\s*\(/,
  /document\.write/,
  /window\.location\s*=/,
  /innerHTML\s*=/,
  /fromCharCode/,
  /unescape\s*\(/,
  /btoa|atob/,
];

// 의심스러운 도메인 패턴
const SUSPICIOUS_DOMAIN_PATTERNS = [
  /\d{4,}/,                    // 긴 숫자 포함
  /-{2,}/,                     // 연속 하이픈
  /\.(tk|ml|ga|cf|gq)$/i,      // 무료 도메인
  /[а-яА-Я]/,                  // 키릴 문자 (호모그래프 공격)
];

/**
 * URL 분석 결과 타입
 * @typedef {Object} AnalysisResult
 * @property {string} url - 분석된 URL
 * @property {number} riskScore - 위험도 점수 (0-100)
 * @property {string} riskLevel - 위험 레벨 (safe/warning/danger)
 * @property {string} screenshot - Base64 인코딩된 스크린샷
 * @property {Object} details - 상세 분석 결과
 * @property {number} analysisTime - 분석 소요 시간 (ms)
 */

/**
 * URL 유효성 검사
 * @param {string} url
 * @returns {boolean}
 */
function isValidUrl(url) {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * 도메인 위험도 분석
 * @param {string} url
 * @returns {Object}
 */
function analyzeDomain(url) {
  const parsed = new URL(url);
  const domain = parsed.hostname;

  const issues = [];
  let score = 0;

  // IP 주소 직접 접근
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
    issues.push('IP 주소로 직접 접근');
    score += 25;
  }

  // 의심스러운 도메인 패턴
  for (const pattern of SUSPICIOUS_DOMAIN_PATTERNS) {
    if (pattern.test(domain)) {
      issues.push('의심스러운 도메인 패턴');
      score += 15;
      break;
    }
  }

  // 서브도메인 과다
  const subdomains = domain.split('.').length - 2;
  if (subdomains > 3) {
    issues.push(`과다 서브도메인 (${subdomains}개)`);
    score += 10;
  }

  // HTTPS 미사용
  if (parsed.protocol !== 'https:') {
    issues.push('HTTPS 미사용');
    score += 15;
  }

  // 비표준 포트
  if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
    issues.push(`비표준 포트 (${parsed.port})`);
    score += 10;
  }

  return { score: Math.min(score, 40), issues };
}

/**
 * 페이지 콘텐츠 위험도 분석
 * @param {puppeteer.Page} page
 * @returns {Promise<Object>}
 */
async function analyzeContent(page) {
  const issues = [];
  let score = 0;

  try {
    // 페이지 텍스트 추출
    const pageText = await page.evaluate(() => document.body?.innerText || '');

    // 피싱 패턴 검사
    for (const pattern of PHISHING_PATTERNS) {
      if (pattern.test(pageText)) {
        issues.push('피싱 의심 문구 발견');
        score += 20;
        break;
      }
    }

    // 입력 폼 분석
    const formInfo = await page.evaluate(() => {
      const forms = document.querySelectorAll('form');
      const passwordFields = document.querySelectorAll('input[type="password"]');
      const hiddenFields = document.querySelectorAll('input[type="hidden"]');

      return {
        formCount: forms.length,
        hasPasswordField: passwordFields.length > 0,
        hiddenFieldCount: hiddenFields.length,
        hasExternalAction: Array.from(forms).some(f => {
          const action = f.getAttribute('action') || '';
          return action.startsWith('http') && !action.includes(window.location.hostname);
        }),
      };
    });

    if (formInfo.hasPasswordField) {
      issues.push('비밀번호 입력 필드 존재');
      score += 10;
    }

    if (formInfo.hasExternalAction) {
      issues.push('외부 서버로 폼 전송');
      score += 25;
    }

    if (formInfo.hiddenFieldCount > 5) {
      issues.push(`다수의 숨겨진 필드 (${formInfo.hiddenFieldCount}개)`);
      score += 10;
    }

    // 스크립트 분석
    const scripts = await page.evaluate(() => {
      return Array.from(document.scripts).map(s => s.textContent || '').join('\n');
    });

    for (const pattern of MALICIOUS_SCRIPT_PATTERNS) {
      if (pattern.test(scripts)) {
        issues.push('의심스러운 스크립트 패턴');
        score += 15;
        break;
      }
    }

  } catch (error) {
    issues.push(`콘텐츠 분석 오류: ${error.message}`);
  }

  return { score: Math.min(score, 50), issues };
}

/**
 * 네트워크 요청 분석
 * @param {Array} requests
 * @returns {Object}
 */
function analyzeNetworkRequests(requests) {
  const issues = [];
  let score = 0;

  // 외부 도메인 요청 수
  const externalDomains = new Set();
  const suspiciousRequests = [];

  for (const req of requests) {
    try {
      const url = new URL(req.url);
      externalDomains.add(url.hostname);

      // 의심스러운 리소스 타입
      if (req.resourceType === 'script' && url.hostname !== req.originalDomain) {
        suspiciousRequests.push(url.hostname);
      }
    } catch {
      // 무효한 URL 무시
    }
  }

  if (externalDomains.size > 10) {
    issues.push(`다수의 외부 도메인 요청 (${externalDomains.size}개)`);
    score += 10;
  }

  if (suspiciousRequests.length > 0) {
    issues.push(`외부 스크립트 로드 (${suspiciousRequests.length}개)`);
    score += 10;
  }

  return {
    score: Math.min(score, 20),
    issues,
    externalDomains: Array.from(externalDomains),
    requestCount: requests.length,
  };
}

/**
 * 위험 레벨 판정
 * @param {number} score
 * @returns {string}
 */
function determineRiskLevel(score) {
  if (score <= RISK_THRESHOLDS.SAFE) return 'safe';
  if (score <= RISK_THRESHOLDS.WARNING) return 'warning';
  return 'danger';
}

/**
 * URL 샌드박스 분석 실행
 * @param {string} url - 분석할 URL
 * @param {Object} options - 분석 옵션
 * @param {number} options.timeout - 타임아웃 (ms), 기본 30000
 * @param {boolean} options.takeScreenshot - 스크린샷 촬영 여부, 기본 true
 * @returns {Promise<AnalysisResult>}
 */
export async function analyzeUrl(url, options = {}) {
  const startTime = Date.now();
  const timeout = options.timeout || 30000;
  const takeScreenshot = options.takeScreenshot !== false;

  // URL 유효성 검사
  if (!isValidUrl(url)) {
    throw new Error('유효하지 않은 URL 형식입니다.');
  }

  let browser = null;
  const networkRequests = [];

  try {
    // Puppeteer 브라우저 시작 (샌드박스 모드)
    browser = await puppeteer.launch({
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1280,720',
        // 보안 강화 옵션
        '--disable-extensions',
        '--disable-plugins',
        '--disable-sync',
        '--disable-translate',
        '--disable-background-networking',
        // MacOS 호환성
        '--single-process',
      ],
    });

    const page = await browser.newPage();

    // 타임아웃 설정
    page.setDefaultNavigationTimeout(timeout);
    page.setDefaultTimeout(timeout);

    // User-Agent 설정 (일반 브라우저로 위장)
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    );

    // 뷰포트 설정
    await page.setViewport({ width: 1280, height: 720 });

    // 네트워크 요청 수집
    const originalDomain = new URL(url).hostname;
    page.on('request', (request) => {
      networkRequests.push({
        url: request.url(),
        resourceType: request.resourceType(),
        originalDomain,
      });
    });

    // 페이지 로드
    let navigationError = null;
    try {
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout,
      });
    } catch (error) {
      navigationError = error.message;
    }

    // 분석 수행
    const domainAnalysis = analyzeDomain(url);
    const contentAnalysis = await analyzeContent(page);
    const networkAnalysis = analyzeNetworkRequests(networkRequests);

    // 네비게이션 오류 시 추가 점수
    let navigationScore = 0;
    const navigationIssues = [];
    if (navigationError) {
      if (navigationError.includes('timeout')) {
        navigationIssues.push('페이지 로드 타임아웃');
        navigationScore = 10;
      } else if (navigationError.includes('net::ERR_')) {
        navigationIssues.push('네트워크 오류');
        navigationScore = 5;
      }
    }

    // 종합 위험도 계산
    const totalScore = Math.min(
      domainAnalysis.score +
      contentAnalysis.score +
      networkAnalysis.score +
      navigationScore,
      100
    );

    // 스크린샷 촬영
    let screenshot = null;
    if (takeScreenshot) {
      try {
        const screenshotBuffer = await page.screenshot({
          type: 'png',
          fullPage: false,
        });
        screenshot = screenshotBuffer.toString('base64');
      } catch {
        // 스크린샷 실패 시 무시
      }
    }

    const analysisTime = Date.now() - startTime;

    // 휴리스틱 분석 결과
    const heuristicResult = {
      url,
      riskScore: totalScore,
      riskLevel: determineRiskLevel(totalScore),
      screenshot,
      details: {
        domain: {
          score: domainAnalysis.score,
          issues: domainAnalysis.issues,
        },
        content: {
          score: contentAnalysis.score,
          issues: contentAnalysis.issues,
        },
        network: {
          score: networkAnalysis.score,
          issues: networkAnalysis.issues,
          externalDomains: networkAnalysis.externalDomains,
          requestCount: networkAnalysis.requestCount,
        },
        navigation: {
          score: navigationScore,
          issues: navigationIssues,
          error: navigationError,
        },
      },
      analysisTime,
      analyzedAt: new Date().toISOString(),
    };

    // AI 분석 수행 (옵션에 따라)
    if (options.useAI !== false) {
      try {
        console.log('[AI 분석] Gemini 3 Flash로 추가 분석 중...');

        const aiResult = await analyzeWithAI({
          url,
          screenshot,
          pageInfo: {
            title: await page.title().catch(() => ''),
            finalUrl: page.url(),
            redirectCount: networkRequests.filter(r =>
              r.resourceType === 'document' && r.url !== url
            ).length,
            externalDomains: networkAnalysis.externalDomains,
          },
          preliminaryAnalysis: {
            riskScore: totalScore,
            riskLevel: determineRiskLevel(totalScore),
            domainIssues: domainAnalysis.issues,
            contentIssues: contentAnalysis.issues,
            networkIssues: networkAnalysis.issues,
          },
        });

        if (aiResult.enabled) {
          console.log(`[AI 분석 완료] AI 위험도: ${aiResult.analysis?.riskScore}, 신뢰도: ${aiResult.analysis?.confidence}%`);
          return mergeAnalysisResults(heuristicResult, aiResult);
        }
      } catch (aiError) {
        console.error('[AI 분석 오류]', aiError.message);
        // AI 분석 실패해도 휴리스틱 결과 반환
      }
    }

    return heuristicResult;

  } finally {
    if (browser) {
      await browser.close();
    }
  }
}

/**
 * 빠른 URL 검사 (브라우저 없이)
 * @param {string} url
 * @returns {Object}
 */
export function quickCheck(url) {
  if (!isValidUrl(url)) {
    return {
      url,
      valid: false,
      riskScore: 0,
      riskLevel: 'unknown',
      message: '유효하지 않은 URL 형식',
    };
  }

  const domainAnalysis = analyzeDomain(url);
  const riskScore = domainAnalysis.score;

  return {
    url,
    valid: true,
    riskScore,
    riskLevel: determineRiskLevel(riskScore),
    issues: domainAnalysis.issues,
    message: domainAnalysis.issues.length > 0
      ? '도메인 분석에서 위험 요소 발견'
      : '도메인 분석 통과',
  };
}
