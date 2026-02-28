"use strict";

process.env.OPENSSL_MODULES = "C:\\vcpkg\\installed\\x64-windows\\bin\\ossl-modules";
process.env.OPENSSL_CONF    = "C:\\vcpkg\\installed\\x64-windows\\share\\openssl\\openssl.cnf";

// sonra require'lar:
const dgram = require("node:dgram");
const { QUICContext } = require("./build/Release/quic.node");