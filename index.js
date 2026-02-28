"use strict";

const path = require("node:path");

if (process.platform === "win32") {
  const root = process.env.OPENSSL_ROOT_DIR || "C:\\vcpkg\\installed\\x64-windows";
  const binDir = process.env.OPENSSL_BIN || path.join(root, "bin");
  process.env.OPENSSL_MODULES = process.env.OPENSSL_MODULES || path.join(binDir, "ossl-modules");
  process.env.OPENSSL_CONF = process.env.OPENSSL_CONF || path.join(root, "share", "openssl", "openssl.cnf");
  process.env.PATH = `${binDir};${process.env.PATH || ""}`;
}

// sonra require'lar:
const dgram = require("node:dgram");
const { QUICContext } = require("./build/Release/quic.node");