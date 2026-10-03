"use strict";
// Picket SDK (zero deps): exception capture and custom events.
// Env: PICKET_ENDPOINT (required), PICKET_TOKEN (required),
// PICKET_HOST_ID, PICKET_SERVICE, PICKET_ENVIRONMENT.

const http = require("http");
const https = require("https");
const os = require("os");

function env(name, dflt) {
  // pre-rename WATCHTOWER_* names still work as a fallback
  return process.env[name] || process.env[name.replace("PICKET_", "WATCHTOWER_")] || dflt;
}

class Client {
  constructor(opts) {
    opts = opts || {};
    this.endpoint = (opts.endpoint || env("PICKET_ENDPOINT", "")).replace(/\/$/, "");
    this.token = opts.token || env("PICKET_TOKEN", "");
    this.host_id = opts.host_id || env("PICKET_HOST_ID", os.hostname());
    this.service = opts.service || env("PICKET_SERVICE", "app");
    this.environment = opts.environment || env("PICKET_ENVIRONMENT", "prod");
  }

  capture(level, type, message, frames) {
    // frames: [{file, line, function}] — innermost first
    return this._post("/v1/errors", {
      host_id: this.host_id,
      service: this.service,
      environment: this.environment,
      exception: {
        type,
        message,
        level,
        frames: frames || [],
      },
    });
  }

  // Emit a custom event (POST /v1/events).
  // event: { kind: "payment.request_failed", summary, severity?, subject?,
  //          attributes?, measurements?, id?, ts?, source?, environment? }
  captureEvent(event) {
    const e = Object.assign(
      { severity: "info", source: this.service, environment: this.environment },
      event || {}
    );
    return this._post("/v1/events", e);
  }

  _post(path, payload) {
    return new Promise((resolve) => {
      if (!this.endpoint || !this.token) {
        return resolve(false);
      }
      const body = JSON.stringify(payload);
      const url = new URL(this.endpoint + path);
      const lib = url.protocol === "https:" ? https : http;
      let attempts = 0;
      const send = () => {
        const req = lib.request(
          {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": "Bearer " + this.token,
              "Content-Length": Buffer.byteLength(body),
            },
            timeout: 10000,
          },
          (res) => {
            res.resume();
            resolve(res.statusCode >= 200 && res.statusCode < 300);
          }
        );
        req.on("error", () => {
          attempts += 1;
          if (attempts < 2) {
            setTimeout(send, 200);
          } else {
            resolve(false);
          }
        });
        req.on("timeout", () => req.destroy());
        req.write(body);
        req.end();
      };
      send();
    });
  }
}

module.exports = { Client };
