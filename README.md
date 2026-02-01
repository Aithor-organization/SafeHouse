# Safe-Link Sandbox

URL 안전성 분석 샌드박스 API - AI 기반 피싱/스캠 탐지 시스템

## 개요

Safe-Link Sandbox는 의심스러운 URL을 안전한 서버 환경에서 분석하여 피싱, 스캠, 악성코드 위험을 탐지하는 서비스입니다.

### 주요 기능

- **샌드박스 분석**: Puppeteer 기반 격리된 환경에서 URL 렌더링
- **위험도 점수화**: 0-100 점수로 위험 수준 평가
- **스크린샷 캡처**: 페이지 미리보기 이미지 제공
- **AI 분석**: Gemini 3 Flash 모델을 활용한 지능형 위협 탐지
- **하이브리드 분석**: 휴리스틱 분석 + AI 분석 결합

## 설치

```bash
# 의존성 설치
npm install

# 환경 변수 설정
cp .env.example .env
# .env 파일에 OPENROUTER_API_KEY 추가
```

## 환경 변수

| 변수명 | 필수 | 설명 |
|--------|------|------|
| `OPENROUTER_API_KEY` | O | OpenRouter API 키 ([발급](https://openrouter.ai/keys)) |
| `PORT` | X | 서버 포트 (기본: 4000) |
| `CORS_ORIGIN` | X | CORS 허용 origin (기본: *) |
| `NODE_ENV` | X | 실행 환경 (기본: development) |

## 실행

```bash
# 개발 모드 (자동 재시작)
npm run dev

# 프로덕션 모드
npm start
```

## API 엔드포인트

### GET /health
서버 상태 확인

### POST /api/analyze
URL 전체 분석 (샌드박스 + AI)

**요청:**
```json
{
  "url": "https://example.com",
  "options": {
    "timeout": 30000,
    "takeScreenshot": true,
    "useAI": true
  }
}
```

**응답:**
```json
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "riskScore": 25,
    "riskLevel": "safe",
    "screenshot": "base64...",
    "details": {
      "domain": { "score": 0, "issues": [] },
      "content": { "score": 15, "issues": ["비밀번호 입력 필드 존재"] },
      "network": { "score": 10, "issues": [] }
    },
    "aiAnalysis": {
      "enabled": true,
      "model": "google/gemini-3-flash-preview",
      "score": 20,
      "summary": "안전한 사이트로 판단됩니다.",
      "findings": [...],
      "recommendations": [...],
      "confidence": 85
    }
  }
}
```

### POST /api/quick-check
빠른 도메인 검사 (브라우저 미사용)

**요청:**
```json
{
  "url": "https://example.com"
}
```

### POST /api/batch-check
여러 URL 일괄 검사

**요청:**
```json
{
  "urls": ["https://example1.com", "https://example2.com"]
}
```

## 위험도 수준

| 점수 | 레벨 | 설명 |
|------|------|------|
| 0-30 | `safe` | 안전 |
| 31-70 | `warning` | 주의 필요 |
| 71-100 | `danger` | 위험 |

## 분석 항목

### 휴리스틱 분석
- **도메인**: IP 접근, 무료 도메인, HTTPS 미사용
- **콘텐츠**: 피싱 문구, 비밀번호 필드, 외부 폼 전송
- **네트워크**: 외부 도메인 요청, 외부 스크립트 로드

### AI 분석 (Gemini 3 Flash)
- 피싱 패턴 인식
- 스캠 문구 탐지
- 시각적 위험 요소 분석
- 종합 위험도 평가

## 기술 스택

- **Runtime**: Node.js 20+
- **Framework**: Express.js
- **Browser**: Puppeteer
- **AI**: OpenRouter API (Gemini 3 Flash)
- **Security**: Helmet, Rate Limiting

## 라이선스

MIT
