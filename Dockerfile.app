# Stage 1: Build the React app
FROM node:20-alpine AS builder
WORKDIR /app

# Copy package files first (layer caching)
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Copy source and build
COPY frontend/ .

# Accept backend API URL as build arg
ARG REACT_APP_API_URL=""
ENV REACT_APP_API_URL=$REACT_APP_API_URL

RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine

COPY deploy/nginx-app.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/build /usr/share/nginx/html

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:3000/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
