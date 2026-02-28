"use strict";

const path = require("node:path");

function configureOpenSSLForWindows() {
  if (process.platform !== "win32") return;

  const root = process.env.OPENSSL_ROOT_DIR || "C:\\vcpkg\\installed\\x64-windows";
  const binDir = process.env.OPENSSL_BIN || path.join(root, "bin");
  const modulesDir = process.env.OPENSSL_MODULES || path.join(binDir, "ossl-modules");
  const conf = process.env.OPENSSL_CONF || path.join(root, "share", "openssl", "openssl.cnf");

  process.env.OPENSSL_MODULES = modulesDir;
  process.env.OPENSSL_CONF = conf;
  process.env.PATH = `${binDir};${process.env.PATH || ""}`;
}

configureOpenSSLForWindows();

const dgram = require("node:dgram");
const { QUICContext } = require("./build/Release/quic.node");

// ====== CONFIG ======
const HOST = process.env.HOST || "0.0.0.0";
const PORT = Number(process.env.PORT || 7844);

const CERT = process.env.CERT || path.join(__dirname, "certs", "server.crt");
const KEY  = process.env.KEY  || path.join(__dirname, "certs", "server.key");
const CA   = process.env.CA   || path.join(__dirname, "certs", "ca.crt");

const ALPN = process.env.ALPN || "fitfak-rpc/1";
const MTU  = Number(process.env.MTU || 1200);

// ====== UDP socket ======
const udp = dgram.createSocket("udp4");

// ====== QUIC context/session ======
const ctx = new QUICContext({
  server: true,
  cert: CERT,
  key: KEY,
  caCert: CA,
  verifyPeer: true,          // mTLS doğrula
  requirePeerCert: true,     // client cert zorunlu
  verifyDepth: 8,
  alpn: ALPN,
});

const ses = ctx.createSession({ mtu: MTU });

// ====== send helper ======
let peer = null; // {address, port}

function flushOutgoing() {
  const outs = ses.drainOutgoing();
  if (!outs || outs.length === 0) return;
  if (!peer) return; // henüz peer yok
  for (const b of outs) {
    udp.send(b, peer.port, peer.address);
  }
}

function pump() {
  ses.pump();
  flushOutgoing();
}

// QUIC zamanlayıcıları için periyodik pump
const pumpTimer = setInterval(pump, 5);

// ====== UDP events ======
udp.on("error", (e) => {
  console.error("[udp] error:", e);
});

udp.on("message", (msg, rinfo) => {
  // Bu örnekte single-peer test: ilk geleni peer seçiyoruz.
  if (!peer) {
    peer = { address: rinfo.address, port: rinfo.port };
    console.log(`[server] peer selected ${peer.address}:${peer.port}`);
  }

  // Başka peer gelirse ignore (test basit olsun)
  if (peer.address !== rinfo.address || peer.port !== rinfo.port) return;

  ses.feedDatagram(msg);
  pump();

  // plaintext al
  const plains = ses.takePlaintext();
  for (const p of plains) {
    const s = p.toString("utf8");
    console.log("[server] RX:", JSON.stringify(s));

    // echo yanıt
    if (ses.isHandshakeDone()) {
      const reply = Buffer.from("echo:" + s, "utf8");
      try {
        ses.sendPlaintext(reply);
      } catch (err) {
        console.error("[server] sendPlaintext err:", err?.message || err);
      }
      pump();
    }
  }

  if (ses.isHandshakeDone()) {
    console.log("[server] handshake done, peerCN =", ses.peerCN);
  } else {
    const le = ses.getLastError();
    if (le) console.log("[server] lastError:", le);
  }
});

udp.bind(PORT, HOST, () => {
  console.log(`[server] udp bound ${HOST}:${PORT}`);
  console.log("[server] cert:", CERT);
  console.log("[server] ca  :", CA);
  console.log("[server] alpn:", ALPN, "mtu:", MTU);
});

// graceful shutdown
process.on("SIGINT", () => {
  clearInterval(pumpTimer);
  try { udp.close(); } catch {}
  process.exit(0);
});