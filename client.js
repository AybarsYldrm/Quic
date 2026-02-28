"use strict";

const dgram = require("node:dgram");
const path = require("node:path");
const { QUICContext } = require("./build/Release/quic.node");

// ====== CONFIG ======
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 7844);

const CLIENT_CERT = process.env.CLIENT_CERT || path.join(__dirname, "certs", "client.crt");
const CLIENT_KEY  = process.env.CLIENT_KEY  || path.join(__dirname, "certs", "client.key");
const CA          = process.env.CA          || path.join(__dirname, "certs", "ca.crt");

const ALPN = process.env.ALPN || "fitfak-rpc/1";
const MTU  = Number(process.env.MTU || 1200);

// SNI/hostname verify için “serverName”
// - localhost sertifikası ise "localhost"
// - nat.fitfak.net sertifikası ise "nat.fitfak.net"
const SERVER_NAME = process.env.SERVER_NAME || "localhost";

// ====== UDP socket ======
const udp = dgram.createSocket("udp4");

// QUIC client context
const ctx = new QUICContext({
  server: false,
  clientCert: CLIENT_CERT,
  clientKey: CLIENT_KEY,
  caCert: CA,
  verifyPeer: true,
  verifyDepth: 8,
  alpn: ALPN,
});

const ses = ctx.createSession({
  serverName: SERVER_NAME,
  mtu: MTU,
});

udp.on("error", (e) => console.error("[udp] error:", e));

function flushOutgoing() {
  const outs = ses.drainOutgoing();
  if (!outs || outs.length === 0) return;
  for (const b of outs) udp.send(b, PORT, HOST);
}

function pump() {
  ses.pump();
  flushOutgoing();
}

const pumpTimer = setInterval(pump, 5);

udp.on("message", (msg) => {
  ses.feedDatagram(msg);
  pump();

  const plains = ses.takePlaintext();
  for (const p of plains) {
    console.log("[client] RX:", JSON.stringify(p.toString("utf8")));
  }

  if (ses.isHandshakeDone()) {
    // handshake tamamlandıysa bir kez “hello” gönder
    if (!globalThis.__sentOnce) {
      globalThis.__sentOnce = true;
      console.log("[client] handshake done, sending hello...");
      try {
        ses.sendPlaintext(Buffer.from("hello-from-client", "utf8"));
      } catch (err) {
        console.error("[client] sendPlaintext err:", err?.message || err);
      }
      pump();
    }
  } else {
    const le = ses.getLastError();
    if (le) console.log("[client] lastError:", le);
  }
});

// Client UDP bind: random port
udp.bind(0, "0.0.0.0", () => {
  const addr = udp.address();
  console.log(`[client] udp bound ${addr.address}:${addr.port} -> ${HOST}:${PORT}`);
  console.log("[client] serverName:", SERVER_NAME);
  console.log("[client] cert:", CLIENT_CERT);
  console.log("[client] ca  :", CA);
  console.log("[client] alpn:", ALPN, "mtu:", MTU);

  // createSession sonrası ilk outbound datagramlar çıkmış olabilir
  pump();
});

process.on("SIGINT", () => {
  clearInterval(pumpTimer);
  try { udp.close(); } catch {}
  process.exit(0);
});