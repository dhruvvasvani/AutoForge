FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG VITE_API_URL=/api
ARG VITE_ANALYZER_URL=/analyzer
ARG VITE_WEBHOOK_URL=/webhook
ENV VITE_API_URL=${VITE_API_URL} \
    VITE_ANALYZER_URL=${VITE_ANALYZER_URL} \
    VITE_WEBHOOK_URL=${VITE_WEBHOOK_URL}
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/health || exit 1
