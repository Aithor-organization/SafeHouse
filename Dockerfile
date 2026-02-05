# ============================================
# Safe-Link Sandbox - Production Dockerfile
# Multi-stage build: Frontend + Backend + Puppeteer
# ============================================

# Stage 1: Build Frontend
FROM node:20-slim AS frontend-builder

WORKDIR /app/frontend

# Frontend 의존성 설치
COPY frontend/package*.json ./
RUN npm ci

# Frontend 빌드
COPY frontend/ ./
RUN npm run build

# ============================================
# Stage 2: Production Runtime
# ============================================
FROM node:20-slim AS production

# Puppeteer 의존성 설치 (Chromium 포함)
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-ipafont-gothic \
    fonts-wqy-zenhei \
    fonts-thai-tlwg \
    fonts-kacst \
    fonts-freefont-ttf \
    fonts-noto-cjk \
    libxss1 \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Puppeteer가 시스템 Chromium 사용하도록 설정
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app

# Backend 의존성 설치
COPY package*.json ./
RUN npm ci --only=production

# Backend 소스 복사
COPY *.js ./
COPY .env.example ./.env.example

# Frontend 빌드 결과물 복사
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# 포트 설정
ENV PORT=4000
ENV SANDBOX_PORT=4000
ENV NODE_ENV=production

EXPOSE 4000

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "fetch('http://localhost:4000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

# 서버 실행
CMD ["node", "sandbox-server.js"]
