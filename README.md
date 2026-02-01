# Safe-Link Sandbox MVP

URL 안전성 분석 샌드박스 API 서비스

## 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                    Safe-Link Sandbox API                     │
│                     (localhost:4000)                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Express   │  │   Helmet    │  │    Rate Limiter     │  │
│  │   Server    │  │  (보안헤더) │  │   (30 req/min)      │  │
│  └──────┬──────┘  └─────────────┘  └─────────────────────┘  │
│         │                                                    │
│  ┌──────┴──────────────────────────────────────────────┐    │
│  │                    API Routes                        │    │
│  │  POST /api/analyze      → 전체 분석 (Puppeteer)     │    │
│  │  POST /api/quick-check  → 빠른 검사 (도메인만)      │    │
│  │  POST /api/batch-check  → 배치 검사 (최대 10개)     │    │
│  │  GET  /health           → 헬스체크                  │    │
│  └──────┬───────────────────────────────────────────────┘    │
│         │                                                    │
│  ┌──────┴──────────────────────────────────────────────┐    │
│  │                   Analyzer Module                    │    │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────┐ │    │
│  │  │  Domain    │  │  Content   │  │   Network      │ │    │
│  │  │  Analysis  │  │  Analysis  │  │   Analysis     │ │    │
│  │  └────────────┘  └────────────┘  └────────────────┘ │    │
│  │                       │                              │    │
│  │              ┌────────┴────────┐                     │    │
│  │              │    Puppeteer    │                     │    │
│  │              │    Sandbox      │                     │    │
│  │              │  (Headless)     │                     │    │
│  │              └─────────────────┘                     │    │
│  └──────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## 빠른 시작

```bash
# 의존성 설치
npm install

# 서버 시작
npm start

# 개발 모드 (watch)
npm run dev
```

## API 엔드포인트

### 1. 전체 분석 (POST /api/analyze)

Puppeteer 샌드박스에서 URL을 로드하고 종합 분석

```bash
curl -X POST http://localhost:4000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**응답 예시:**
```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "riskScore": 15,
    "riskLevel": "safe",
    "screenshot": "base64...",
    "details": {
      "domain": { "score": 0, "issues": [] },
      "content": { "score": 10, "issues": ["비밀번호 입력 필드 존재"] },
      "network": { "score": 5, "issues": [], "requestCount": 12 },
      "navigation": { "score": 0, "issues": [], "error": null }
    },
    "analysisTime": 3500,
    "analyzedAt": "2024-01-15T10:30:00.000Z"
  }
}
```

### 2. 빠른 검사 (POST /api/quick-check)

브라우저 없이 도메인만 분석 (빠른 응답)

```bash
curl -X POST http://localhost:4000/api/quick-check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.tk"}'
```

### 3. 배치 검사 (POST /api/batch-check)

여러 URL 동시 검사 (최대 10개)

```bash
curl -X POST http://localhost:4000/api/batch-check \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "https://suspicious.tk"]}'
```

## 위험도 점수 체계

| 레벨 | 점수 범위 | 설명 |
|------|-----------|------|
| `safe` | 0-30 | 안전함 |
| `warning` | 31-70 | 주의 필요 |
| `danger` | 71-100 | 위험 |

## 분석 항목

### 도메인 분석 (최대 40점)
- IP 주소 직접 접근 (+25)
- 의심스러운 도메인 패턴 (+15)
- 과다 서브도메인 (+10)
- HTTPS 미사용 (+15)
- 비표준 포트 (+10)

### 콘텐츠 분석 (최대 50점)
- 피싱 의심 문구 (+20)
- 비밀번호 입력 필드 (+10)
- 외부 서버로 폼 전송 (+25)
- 다수의 숨겨진 필드 (+10)
- 의심스러운 스크립트 패턴 (+15)

### 네트워크 분석 (최대 20점)
- 다수의 외부 도메인 요청 (+10)
- 외부 스크립트 로드 (+10)

## 제약사항

- **타임아웃**: 30초
- **Rate Limit**: 분당 30회
- **URL 길이**: 최대 2048자
- **배치 검사**: 최대 10개 URL

## 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `PORT` | 4000 | 서버 포트 |
| `CORS_ORIGIN` | * | CORS 허용 오리진 |
| `NODE_ENV` | production | 환경 (development시 상세 에러) |

## 프로젝트 구조

```
safe-link-sandbox/
├── server.js      # Express 서버 (미들웨어, 라우팅)
├── analyzer.js    # Puppeteer 분석 모듈
├── package.json   # 의존성
└── README.md      # 문서
```

## 보안 고려사항

1. **샌드박스 격리**: Puppeteer headless 모드 + 보안 플래그
2. **Rate Limiting**: DoS 방지
3. **입력 검증**: URL 유효성 및 길이 제한
4. **보안 헤더**: Helmet 미들웨어 적용
5. **에러 노출 방지**: production 환경에서 상세 에러 숨김
