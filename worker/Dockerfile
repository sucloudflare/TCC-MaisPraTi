FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --no-audit --no-fund
# instala navegadores do playwright
RUN npx playwright install --with-deps

COPY . .

# diretórios para reports/screenshots (mapeados por docker-compose)
RUN mkdir -p /data/reports /data/screenshots

CMD ["node", "worker.js"]
