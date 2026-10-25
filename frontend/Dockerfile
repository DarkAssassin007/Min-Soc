# Mini SOC dashboard image: build the Vite bundle, serve it with nginx and
# reverse-proxy /api and /ws to the backend container (single origin, so the
# browser keeps a strict Content-Security-Policy and no CORS is needed).
FROM node:20-alpine AS build

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
