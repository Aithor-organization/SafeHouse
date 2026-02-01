/**
 * AI-Powered URL Analysis Module
 * OpenRouter API를 통한 Gemini 3 Flash 기반 분석
 */

// OpenRouter API 설정
const OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/chat/completions';
const MODEL_NAME = 'google/gemini-3-flash-preview';

/**
 * OpenRouter API를 통해 AI 분석 수행
 * @param {Object} analysisData - 분석할 데이터
 * @param {string} analysisData.url - 분석 대상 URL
 * @param {string} analysisData.screenshot - Base64 스크린샷 (선택)
 * @param {Object} analysisData.pageInfo - 페이지 정보
 * @param {Object} analysisData.preliminaryAnalysis - 기존 휴리스틱 분석 결과
 * @returns {Promise<Object>} AI 분석 결과
 */
export async function analyzeWithAI(analysisData) {
  const apiKey = process.env.OPENROUTER_API_KEY;

  if (!apiKey) {
    console.warn('[AI 분석] OPENROUTER_API_KEY가 설정되지 않았습니다. AI 분석을 건너뜁니다.');
    return {
      enabled: false,
      reason: 'API 키 미설정',
    };
  }

  try {
    const prompt = buildAnalysisPrompt(analysisData);
    const messages = buildMessages(prompt, analysisData.screenshot);

    const response = await fetch(OPENROUTER_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'https://safe-link-sandbox.local',
        'X-Title': 'Safe-Link Sandbox',
      },
      body: JSON.stringify({
        model: MODEL_NAME,
        messages,
        max_tokens: 2048,
        temperature: 0.3, // 일관된 분석을 위해 낮은 temperature
        response_format: { type: 'json_object' },
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenRouter API 오류: ${response.status} - ${errorText}`);
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;

    if (!content) {
      throw new Error('AI 응답이 비어있습니다.');
    }

    // JSON 파싱
    const aiResult = parseAIResponse(content);

    return {
      enabled: true,
      model: MODEL_NAME,
      analysis: aiResult,
      usage: data.usage,
    };

  } catch (error) {
    console.error('[AI 분석 오류]', error.message);
    return {
      enabled: false,
      error: error.message,
    };
  }
}

/**
 * 분석 프롬프트 생성
 * @param {Object} data
 * @returns {string}
 */
function buildAnalysisPrompt(data) {
  const { url, pageInfo, preliminaryAnalysis } = data;

  return `당신은 사이버 보안 전문가입니다. 다음 URL과 웹페이지 정보를 분석하여 피싱, 스캠, 악성코드 위험도를 평가해주세요.

## 분석 대상
- **URL**: ${url}
- **페이지 제목**: ${pageInfo?.title || '없음'}
- **최종 URL**: ${pageInfo?.finalUrl || url}
- **리다이렉트 횟수**: ${pageInfo?.redirectCount || 0}
- **외부 도메인 수**: ${pageInfo?.externalDomains?.length || 0}

## 기존 휴리스틱 분석 결과
${JSON.stringify(preliminaryAnalysis, null, 2)}

## 분석 요청
위 정보와 제공된 스크린샷(있는 경우)을 바탕으로 다음을 분석해주세요:

1. **피싱 가능성**: 합법적인 사이트를 사칭하고 있는지
2. **스캠 패턴**: 사기성 문구나 긴급함을 유도하는 패턴
3. **기술적 위험**: 악성 스크립트, 의심스러운 리다이렉트
4. **시각적 위험**: 로고 위조, 가짜 보안 배지, 긴급 경고 등
5. **전체 평가**: 종합적인 위험도 판단

## 응답 형식 (JSON)
{
  "riskScore": 0-100 사이의 숫자,
  "riskLevel": "safe" | "warning" | "danger",
  "summary": "한 문장 요약",
  "findings": [
    {
      "category": "phishing" | "scam" | "malware" | "suspicious" | "safe",
      "severity": "low" | "medium" | "high",
      "description": "발견 내용 설명"
    }
  ],
  "recommendations": ["사용자에게 권장하는 행동 1", "행동 2"],
  "confidence": 0-100 사이의 신뢰도
}`;
}

/**
 * 메시지 배열 생성 (이미지 포함 가능)
 * @param {string} prompt
 * @param {string} screenshot - Base64 이미지 (선택)
 * @returns {Array}
 */
function buildMessages(prompt, screenshot) {
  const content = [];

  // 텍스트 프롬프트
  content.push({
    type: 'text',
    text: prompt,
  });

  // 스크린샷이 있으면 이미지로 추가
  if (screenshot) {
    content.push({
      type: 'image_url',
      image_url: {
        url: `data:image/png;base64,${screenshot}`,
      },
    });
  }

  return [
    {
      role: 'system',
      content: '당신은 사이버 보안 전문가로, 웹사이트의 안전성을 분석합니다. 항상 JSON 형식으로 응답하세요.',
    },
    {
      role: 'user',
      content,
    },
  ];
}

/**
 * AI 응답 파싱
 * @param {string} content
 * @returns {Object}
 */
function parseAIResponse(content) {
  try {
    // JSON 블록 추출 시도
    const jsonMatch = content.match(/```json\n?([\s\S]*?)\n?```/) ||
                      content.match(/\{[\s\S]*\}/);

    const jsonStr = jsonMatch ? (jsonMatch[1] || jsonMatch[0]) : content;
    return JSON.parse(jsonStr);
  } catch (error) {
    // 파싱 실패 시 기본 구조 반환
    return {
      riskScore: 50,
      riskLevel: 'warning',
      summary: content.substring(0, 200),
      findings: [{
        category: 'suspicious',
        severity: 'medium',
        description: 'AI 분석 결과를 파싱할 수 없습니다.',
      }],
      recommendations: ['수동으로 확인이 필요합니다.'],
      confidence: 30,
      rawResponse: content,
    };
  }
}

/**
 * AI 분석 결과와 휴리스틱 분석 결과 병합
 * @param {Object} heuristicResult - 기존 휴리스틱 분석 결과
 * @param {Object} aiResult - AI 분석 결과
 * @returns {Object} 병합된 최종 결과
 */
export function mergeAnalysisResults(heuristicResult, aiResult) {
  if (!aiResult.enabled || !aiResult.analysis) {
    return {
      ...heuristicResult,
      aiAnalysis: aiResult,
    };
  }

  const ai = aiResult.analysis;

  // 위험도 점수 가중 평균 (휴리스틱 40%, AI 60%)
  const combinedScore = Math.round(
    heuristicResult.riskScore * 0.4 + ai.riskScore * 0.6
  );

  // 위험 레벨 결정 (더 높은 위험도 채택)
  const riskLevels = { safe: 0, warning: 1, danger: 2 };
  const heuristicLevel = riskLevels[heuristicResult.riskLevel] || 0;
  const aiLevel = riskLevels[ai.riskLevel] || 0;
  const finalLevel = Math.max(heuristicLevel, aiLevel);
  const combinedRiskLevel = Object.keys(riskLevels).find(
    key => riskLevels[key] === finalLevel
  );

  return {
    ...heuristicResult,
    riskScore: combinedScore,
    riskLevel: combinedRiskLevel,
    aiAnalysis: {
      enabled: true,
      model: aiResult.model,
      score: ai.riskScore,
      level: ai.riskLevel,
      summary: ai.summary,
      findings: ai.findings,
      recommendations: ai.recommendations,
      confidence: ai.confidence,
    },
  };
}
