const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const path = require("path");
const app = express();
const port = process.env.PORT || 8080;

const API_URL = process.env.API_URL || "https://app-auditgraph-api.azurewebsites.net";

// Proxy /api requests to backend (pathFilter preserves full path)
app.use(createProxyMiddleware({
  target: API_URL,
  changeOrigin: true,
  pathFilter: "/api",
}));

app.use(express.static(path.join(__dirname, "build")));

// SPA fallback - all routes serve index.html
app.get("/*", (req, res) => {
  res.sendFile(path.join(__dirname, "build", "index.html"));
});

app.listen(port, () => {
  console.log(`Frontend running on port ${port}, proxying /api to ${API_URL}`);
});
