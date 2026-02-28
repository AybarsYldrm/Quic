// src/quic.cc
#include <node_api.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>

#include <string>
#include <vector>
#include <mutex>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
  #include <windows.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x030500000L
  #error "OpenSSL >= 3.5 required for OpenSSL QUIC APIs used here"
#endif

/* ============================================================
   Errors + Diagnostics
   ============================================================ */

static std::string openssl_errs_all() {
  std::string out;
  for (;;) {
    unsigned long e = ERR_get_error();
    if (!e) break;
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    if (!out.empty()) out += " | ";
    out += buf;
  }
  return out;
}

static void throw_err(napi_env env, const char* msg) {
  napi_throw_error(env, nullptr, msg);
}
static void throw_err_str(napi_env env, const std::string& msg) {
  napi_throw_error(env, nullptr, msg.c_str());
}

static std::string getenv_str(const char* k) {
  const char* v = std::getenv(k);
  return v ? std::string(v) : std::string();
}

#ifdef _WIN32
static std::string win_loaded_dll_dir(const char* dllName) {
  HMODULE h = GetModuleHandleA(dllName);
  if (!h) return "";
  char buf[MAX_PATH];
  DWORD n = GetModuleFileNameA(h, buf, MAX_PATH);
  if (!n || n >= MAX_PATH) return "";
  std::string p(buf, buf + n);
  size_t slash = p.find_last_of("\\/");
  if (slash == std::string::npos) return "";
  return p.substr(0, slash);
}
static std::string win_libcrypto_dir() {
  std::string d;
  d = win_loaded_dll_dir("libcrypto-3-x64.dll"); if (!d.empty()) return d;
  d = win_loaded_dll_dir("libcrypto-3.dll");     if (!d.empty()) return d;
  d = win_loaded_dll_dir("libcrypto.dll");       if (!d.empty()) return d;
  return "";
}
static std::string win_libssl_dir() {
  std::string d;
  d = win_loaded_dll_dir("libssl-3-x64.dll"); if (!d.empty()) return d;
  d = win_loaded_dll_dir("libssl-3.dll");     if (!d.empty()) return d;
  d = win_loaded_dll_dir("libssl.dll");       if (!d.empty()) return d;
  return "";
}
#endif

static std::string join_diag() {
  std::string s;
  s += "OpenSSL_version="; s += OpenSSL_version(OPENSSL_VERSION);
  s += " | OpenSSL_dir=";  s += OpenSSL_version(OPENSSL_DIR);
  s += " | OPENSSL_MODULES="; s += getenv_str("OPENSSL_MODULES");
  s += " | OPENSSL_CONF=";    s += getenv_str("OPENSSL_CONF");
#ifdef _WIN32
  {
    std::string d = win_libcrypto_dir();
    if (!d.empty()) { s += " | libcrypto_loaded_dir=" + d; }
  }
  {
    std::string d = win_libssl_dir();
    if (!d.empty()) { s += " | libssl_loaded_dir=" + d; }
  }
#endif
  return s;
}

/* ============================================================
   One-time OpenSSL init + provider handling
   ============================================================ */

static std::once_flag g_ssl_init_once;
static OSSL_PROVIDER* g_prov_default = nullptr;
static OSSL_PROVIDER* g_prov_legacy  = nullptr;
static std::string g_init_diag;

static void openssl_init_once() {
  g_init_diag.clear();

  // Load config (helps provider discovery on many setups)
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr);
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);
  ERR_clear_error();

  // Try loading providers explicitly
  g_prov_default = OSSL_PROVIDER_load(nullptr, "default");
  if (g_prov_default) {
    g_init_diag += "[prov default OK]";
  } else {
    std::string e = openssl_errs_all();
    g_init_diag += "[prov default FAILED]";
    if (!e.empty()) g_init_diag += " " + e;
    ERR_clear_error();
  }

  g_prov_legacy = OSSL_PROVIDER_load(nullptr, "legacy");
  if (g_prov_legacy) {
    g_init_diag += " [prov legacy OK]";
  } else {
    std::string e = openssl_errs_all();
    g_init_diag += " [prov legacy FAILED]";
    if (!e.empty()) g_init_diag += " " + e;
    ERR_clear_error();
  }

  // QUIC methods must exist at runtime (3.5+)
  if (OSSL_QUIC_server_method() && OSSL_QUIC_client_method()) {
    g_init_diag += " [QUIC methods OK]";
  } else {
    g_init_diag += " [QUIC methods MISSING]";
  }

  g_init_diag += " | " + join_diag();
}

/* ============================================================
   N-API helpers
   ============================================================ */

static bool is_object(napi_env env, napi_value v) {
  napi_valuetype t; napi_typeof(env, v, &t); return t == napi_object;
}
static bool is_buffer(napi_env env, napi_value v) {
  bool b=false; napi_is_buffer(env, v, &b); return b;
}
static bool has_named(napi_env env, napi_value obj, const char* k) {
  bool has=false; napi_has_named_property(env, obj, k, &has); return has;
}
static bool get_named_bool(napi_env env, napi_value obj, const char* name, bool& out) {
  if (!has_named(env, obj, name)) return false;
  napi_value v; if (napi_get_named_property(env, obj, name, &v) != napi_ok) return false;
  bool b; if (napi_get_value_bool(env, v, &b) != napi_ok) return false;
  out = b; return true;
}
static bool get_named_uint32(napi_env env, napi_value obj, const char* name, uint32_t& out) {
  if (!has_named(env, obj, name)) return false;
  napi_value v; if (napi_get_named_property(env, obj, name, &v) != napi_ok) return false;
  uint32_t x; if (napi_get_value_uint32(env, v, &x) != napi_ok) return false;
  out = x; return true;
}
static bool get_named_string(napi_env env, napi_value obj, const char* name, std::string& out) {
  if (!has_named(env, obj, name)) return false;
  napi_value v; if (napi_get_named_property(env, obj, name, &v) != napi_ok) return false;
  size_t len=0; if (napi_get_value_string_utf8(env, v, nullptr, 0, &len) != napi_ok) return false;
  out.resize(len);
  if (napi_get_value_string_utf8(env, v, out.data(), len+1, &len) != napi_ok) return false;
  return true;
}
static napi_value make_bool(napi_env env, bool b) {
  napi_value v; napi_get_boolean(env, b, &v); return v;
}
static napi_value make_u32(napi_env env, uint32_t x) {
  napi_value v; napi_create_uint32(env, x, &v); return v;
}
static napi_value make_string(napi_env env, const std::string& s) {
  napi_value v; napi_create_string_utf8(env, s.c_str(), s.size(), &v); return v;
}
static napi_value make_buffer_copy(napi_env env, const uint8_t* data, size_t len) {
  napi_value buf; void* dst=nullptr;
  napi_create_buffer(env, len, &dst, &buf);
  if (len && dst) std::memcpy(dst, data, len);
  return buf;
}

/* ============================================================
   TLS helpers
   ============================================================ */

static bool load_cert_key(SSL_CTX* ctx, const std::string& certPath, const std::string& keyPath) {
  if (SSL_CTX_use_certificate_chain_file(ctx, certPath.c_str()) <= 0) return false;
  if (SSL_CTX_use_PrivateKey_file(ctx, keyPath.c_str(), SSL_FILETYPE_PEM) <= 0) return false;
  if (SSL_CTX_check_private_key(ctx) != 1) return false;
  return true;
}
static bool load_ca(SSL_CTX* ctx, const std::string& caPath) {
  return SSL_CTX_load_verify_locations(ctx, caPath.c_str(), nullptr) == 1;
}
static std::string peer_cn(SSL* ssl) {
  if (!ssl) return "";
  X509* cert = SSL_get0_peer_certificate(ssl);
  if (!cert) return "";
  X509_NAME* subj = X509_get_subject_name(cert);
  if (!subj) return "";
  char buf[256];
  int n = X509_NAME_get_text_by_NID(subj, NID_commonName, buf, sizeof(buf));
  if (n <= 0) return "";
  return std::string(buf, (size_t)n);
}
static std::string mk_alpn_wire(const std::string& alpn) {
  if (alpn.empty() || alpn.size() > 255) return {};
  std::string w;
  w.push_back((char)alpn.size());
  w += alpn;
  return w;
}
static int alpn_select_cb(SSL*, const unsigned char** out, unsigned char* outlen,
                          const unsigned char* in, unsigned int inlen, void* arg) {
  const std::string* wanted = (const std::string*)arg;
  if (!wanted || wanted->empty()) return SSL_TLSEXT_ERR_NOACK;

  const unsigned char* p = in;
  unsigned int left = inlen;

  while (left > 0) {
    unsigned int l = p[0];
    p++; left--;
    if (l > left) break;

    if (l == wanted->size() && std::memcmp(p, wanted->data(), l) == 0) {
      *out = p;
      *outlen = (unsigned char)l;
      return SSL_TLSEXT_ERR_OK;
    }
    p += l;
    left -= l;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

/* ============================================================
   QUIC over Node dgram: BIO_s_dgram_pair (3.5+)
   ============================================================ */

static bool quic_make_dgram_pair(BIO** out_ssl_side, BIO** out_app_side, uint32_t mtu) {
  *out_ssl_side = nullptr;
  *out_app_side = nullptr;

  const BIO_METHOD* m = BIO_s_dgram_pair();
  if (!m) return false;

  BIO* b1 = BIO_new(m);
  BIO* b2 = BIO_new(m);
  if (!b1 || !b2) { if (b1) BIO_free(b1); if (b2) BIO_free(b2); return false; }

  if (BIO_make_bio_pair(b1, b2) != 1) { BIO_free(b1); BIO_free(b2); return false; }

  (void)BIO_ctrl(b1, BIO_CTRL_DGRAM_SET_MTU, (long)mtu, nullptr);
  (void)BIO_ctrl(b2, BIO_CTRL_DGRAM_SET_MTU, (long)mtu, nullptr);

  (void)BIO_dgram_set_no_trunc(b1, 1);
  (void)BIO_dgram_set_no_trunc(b2, 1);

  BIO_set_nbio(b1, 1);
  BIO_set_nbio(b2, 1);

  *out_ssl_side = b1;
  *out_app_side = b2;
  return true;
}

/* ============================================================
   QUICContext / QUICSession
   ============================================================ */

struct QUICContext {
  SSL_CTX* ctx = nullptr;
  bool is_server = false;

  bool verify_peer = true;
  bool require_peer_cert = false;
  int  verify_depth = 5;

  std::string alpn;

  explicit QUICContext(bool server): is_server(server) {}
  ~QUICContext() { if (ctx) SSL_CTX_free(ctx); }
};

struct QUICSession {
  bool is_server = false;

  SSL* listener = nullptr;
  bool listener_ready = false;

  SSL* conn = nullptr;
  SSL* stream = nullptr;

  BIO* net_ssl = nullptr; // owned by SSL after SSL_set_bio
  BIO* net_app = nullptr; // paired app side

  uint32_t mtu = 1200;
  bool handshake_done = false;
  bool stream_ready = false;

  std::string lastError;
  std::string peerCN;

  std::vector<std::vector<uint8_t>> outgoing;
  std::vector<std::vector<uint8_t>> incoming;

  ~QUICSession() {
    if (stream)   { SSL_free(stream); stream = nullptr; }
    if (conn)     { SSL_free(conn); conn = nullptr; }
    if (listener) { SSL_free(listener); listener = nullptr; }
    net_ssl = nullptr;
    net_app = nullptr;
  }
};

static napi_ref QUICContext_ctor_ref;
static napi_ref QUICSession_ctor_ref;

/* ============================================================
   Pump helpers
   ============================================================ */

static void quic_drain_app_out(QUICSession* s) {
  if (!s || !s->net_app) return;

  for (;;) {
    uint8_t buf[2048];
    int n = BIO_read(s->net_app, buf, (int)sizeof(buf));
    if (n > 0) {
      s->outgoing.emplace_back(buf, buf + n);
      continue;
    }
    if (BIO_should_retry(s->net_app)) break;
    break;
  }
}

static void quic_try_make_stream(QUICSession* s) {
  if (!s || !s->conn || s->stream_ready) return;
  if (!s->handshake_done) return;

  SSL_set_default_stream_mode(s->conn, SSL_DEFAULT_STREAM_MODE_AUTO_BIDI);

  if (!s->is_server) {
    s->stream = SSL_new_stream(s->conn, 0);
    if (!s->stream) return;
    s->stream_ready = true;
    return;
  }

  s->stream = SSL_accept_stream(s->conn, 0);
  if (!s->stream) return;
  s->stream_ready = true;
}

static void quic_server_try_accept_conn(QUICSession* s) {
  if (!s || !s->is_server) return;
  if (s->conn || !s->listener) return;

  (void)SSL_handle_events(s->listener);

  if (!s->listener_ready) {
    int lr = SSL_listen(s->listener);
    if (lr == 1) {
      s->listener_ready = true;
    } else {
      int le = SSL_get_error(s->listener, lr);
      if (le == SSL_ERROR_WANT_READ || le == SSL_ERROR_WANT_WRITE) return;

      if (s->lastError.empty()) {
        std::string errs = openssl_errs_all();
        s->lastError = "SSL_listen failed";
        if (!errs.empty()) s->lastError += ": " + errs;
      }
      return;
    }
  }

  SSL* c = SSL_accept_connection(s->listener, 0);
  if (c) {
    s->conn = c;
    (void)SSL_set_blocking_mode(s->conn, 0);
    return;
  }
}

static void quic_pump(QUICSession* s) {
  if (!s) return;

  if (s->is_server) {
    quic_server_try_accept_conn(s);
    quic_drain_app_out(s);
    if (!s->conn) return;
  }

  if (!s->conn) return;

  (void)SSL_handle_events(s->conn);

  if (!s->handshake_done) {
    int r = SSL_do_handshake(s->conn);
    if (r == 1) {
      s->handshake_done = true;
      s->peerCN = peer_cn(s->conn);
    } else {
      int e = SSL_get_error(s->conn, r);
      if (!(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)) {
        if (s->lastError.empty()) {
          std::string errs = openssl_errs_all();
          s->lastError = "handshake failed";
          if (!errs.empty()) s->lastError += ": " + errs;
        }
      }
    }
  }

  quic_try_make_stream(s);

  if (s->stream_ready && s->stream) {
    for (;;) {
      uint8_t buf[4096];
      size_t nread = 0;
      int rr = SSL_read_ex(s->stream, buf, sizeof(buf), &nread);
      if (rr == 1 && nread > 0) {
        s->incoming.emplace_back(buf, buf + nread);
        continue;
      }
      int e = SSL_get_error(s->stream, rr);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) break;
      if (e == SSL_ERROR_ZERO_RETURN) break;

      if (rr <= 0) {
        if (s->lastError.empty()) {
          std::string errs = openssl_errs_all();
          s->lastError = "ssl_read_ex failed";
          if (!errs.empty()) s->lastError += ": " + errs;
        }
      }
      break;
    }
  }

  quic_drain_app_out(s);
}

/* ============================================================
   QUICContext JS: new QUICContext(opts)
   ============================================================ */

static napi_value QUICContext_ctor(napi_env env, napi_callback_info info) {
  size_t argc=1; napi_value args[1]; napi_value jsthis;
  napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);

  if (argc < 1 || !is_object(env, args[0])) {
    throw_err(env, "QUICContext(optionsObject) required");
    return nullptr;
  }

  std::call_once(g_ssl_init_once, openssl_init_once);

  // Runtime version guard: if DLL mismatch, fail loudly here.
  //
  // NOTE:
  // OpenSSL_version_num() for OpenSSL 3.x follows 0xMNN00PP0L (e.g. 3.5.0 -> 0x30500000).
  // The previous constant used an extra nybble (0x0305000000) and incorrectly rejected
  // valid 3.5+ runtimes.
  const uint64_t rnum = (uint64_t)OpenSSL_version_num();
  constexpr uint64_t kMinQuicOpenSSL = 0x30500000ULL; // OpenSSL 3.5.0+
  if (rnum < kMinQuicOpenSSL) {
    std::string s = "OpenSSL runtime < 3.5 (DLL mismatch). ";
    s += join_diag();
    throw_err_str(env, s);
    return nullptr;
  }

  bool server=false;
  get_named_bool(env, args[0], "server", server);

  auto* c = new QUICContext(server);

  get_named_bool(env, args[0], "verifyPeer", c->verify_peer);
  get_named_bool(env, args[0], "requirePeerCert", c->require_peer_cert);

  uint32_t depth=0;
  if (get_named_uint32(env, args[0], "verifyDepth", depth)) c->verify_depth = (int)depth;

  get_named_string(env, args[0], "alpn", c->alpn);

  const SSL_METHOD* method = server ? OSSL_QUIC_server_method() : OSSL_QUIC_client_method();
  if (!method) {
    delete c;
    std::string s = "OSSL_QUIC_*_method() returned NULL (runtime missing QUIC). init_diag=";
    s += g_init_diag;
    throw_err_str(env, s);
    return nullptr;
  }

  c->ctx = SSL_CTX_new(method);
  if (!c->ctx) {
    std::string errs = openssl_errs_all();
    std::string s = "SSL_CTX_new failed";
    if (!errs.empty()) s += ": " + errs;
    s += " | init_diag=" + g_init_diag;
    s += " | " + join_diag();
    delete c;
    throw_err_str(env, s);
    return nullptr;
  }

  SSL_CTX_set_mode(c->ctx, SSL_MODE_RELEASE_BUFFERS);

  std::string certPath, keyPath;

  if (server) {
    if (!get_named_string(env, args[0], "cert", certPath) ||
        !get_named_string(env, args[0], "key",  keyPath)) {
      delete c;
      throw_err(env, "Server mode requires {cert,key}");
      return nullptr;
    }
    if (!load_cert_key(c->ctx, certPath, keyPath)) {
      std::string errs = openssl_errs_all();
      std::string s = "load server cert/key failed";
      if (!errs.empty()) s += ": " + errs;
      s += " | " + join_diag();
      delete c;
      throw_err_str(env, s);
      return nullptr;
    }
  } else {
    if (!get_named_string(env, args[0], "clientCert", certPath) ||
        !get_named_string(env, args[0], "clientKey",  keyPath)) {
      delete c;
      throw_err(env, "Client mode requires {clientCert,clientKey}");
      return nullptr;
    }
    if (!load_cert_key(c->ctx, certPath, keyPath)) {
      std::string errs = openssl_errs_all();
      std::string s = "load client cert/key failed";
      if (!errs.empty()) s += ": " + errs;
      s += " | " + join_diag();
      delete c;
      throw_err_str(env, s);
      return nullptr;
    }
  }

  std::string caPath;
  bool hasCA = get_named_string(env, args[0], "caCert", caPath);

  if (c->verify_peer) {
    if (!hasCA) {
      delete c;
      throw_err(env, "verifyPeer=true requires {caCert}");
      return nullptr;
    }
    if (!load_ca(c->ctx, caPath)) {
      std::string errs = openssl_errs_all();
      std::string s = "load_verify_locations(caCert) failed";
      if (!errs.empty()) s += ": " + errs;
      s += " | " + join_diag();
      delete c;
      throw_err_str(env, s);
      return nullptr;
    }
  } else {
    if (hasCA) (void)load_ca(c->ctx, caPath);
  }

  int vmode = SSL_VERIFY_NONE;
  if (c->verify_peer) {
    vmode = SSL_VERIFY_PEER;
    if (c->is_server && c->require_peer_cert) vmode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }
  SSL_CTX_set_verify(c->ctx, vmode, nullptr);
  SSL_CTX_set_verify_depth(c->ctx, c->verify_depth);

  if (c->is_server && !c->alpn.empty()) {
    SSL_CTX_set_alpn_select_cb(c->ctx, alpn_select_cb, &c->alpn);
  }

  napi_wrap(env, jsthis, c,
    [](napi_env, void* data, void*) { delete (QUICContext*)data; },
    nullptr, nullptr
  );
  return jsthis;
}

/* ============================================================
   QUICContext.createSession(opts)
   ============================================================ */

static napi_value QUICContext_createSession(napi_env env, napi_callback_info info) {
  size_t argc=1; napi_value args[1]; napi_value jsthis;
  napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);

  QUICContext* c=nullptr;
  napi_unwrap(env, jsthis, (void**)&c);
  if (!c || !c->ctx) {
    throw_err(env, "bad this");
    return nullptr;
  }

  auto* s = new QUICSession();
  s->is_server = c->is_server;

  if (argc >= 1 && is_object(env, args[0])) {
    uint32_t mtu=0;
    if (get_named_uint32(env, args[0], "mtu", mtu) && mtu >= 400 && mtu <= 2000)
      s->mtu = mtu;
  }

  if (!quic_make_dgram_pair(&s->net_ssl, &s->net_app, s->mtu)) {
    delete s;
    throw_err(env, "BIO_s_dgram_pair init failed");
    return nullptr;
  }

  if (c->is_server) {
    s->listener = SSL_new_listener(c->ctx, 0);
    if (!s->listener) {
      std::string errs = openssl_errs_all();
      std::string msg = "SSL_new_listener failed";
      if (!errs.empty()) msg += ": " + errs;
      msg += " | init_diag=" + g_init_diag;
      msg += " | " + join_diag();
      delete s;
      throw_err_str(env, msg);
      return nullptr;
    }

    if (!SSL_set_blocking_mode(s->listener, 0)) {
      std::string errs = openssl_errs_all();
      std::string msg = "SSL_set_blocking_mode(listener,0) failed";
      if (!errs.empty()) msg += ": " + errs;
      msg += " | " + join_diag();
      delete s;
      throw_err_str(env, msg);
      return nullptr;
    }

    // Attach BIO (ownership of net_ssl transferred)
    SSL_set_bio(s->listener, s->net_ssl, s->net_ssl);
    s->listener_ready = false;

    quic_drain_app_out(s);
  } else {
    if (argc < 1 || !is_object(env, args[0])) {
      delete s;
      throw_err(env, "client createSession({serverName}) required");
      return nullptr;
    }

    std::string sni;
    if (!get_named_string(env, args[0], "serverName", sni) || sni.empty()) {
      delete s;
      throw_err(env, "createSession: missing serverName");
      return nullptr;
    }

    s->conn = SSL_new(c->ctx);
    if (!s->conn) {
      std::string errs = openssl_errs_all();
      std::string msg = "SSL_new failed";
      if (!errs.empty()) msg += ": " + errs;
      msg += " | init_diag=" + g_init_diag;
      msg += " | " + join_diag();
      delete s;
      throw_err_str(env, msg);
      return nullptr;
    }

    if (!SSL_set_blocking_mode(s->conn, 0)) {
      std::string errs = openssl_errs_all();
      std::string msg = "SSL_set_blocking_mode(conn,0) failed";
      if (!errs.empty()) msg += ": " + errs;
      msg += " | " + join_diag();
      delete s;
      throw_err_str(env, msg);
      return nullptr;
    }

    SSL_set_tlsext_host_name(s->conn, sni.c_str());
    SSL_set1_host(s->conn, sni.c_str());

    if (!c->alpn.empty()) {
      auto wire = mk_alpn_wire(c->alpn);
      if (!wire.empty())
        (void)SSL_set_alpn_protos(s->conn, (const unsigned char*)wire.data(), (unsigned int)wire.size());
    }

    SSL_set_bio(s->conn, s->net_ssl, s->net_ssl); // ownership transfer
    SSL_set_connect_state(s->conn);

    // Kick handshake once (non-blocking)
    int r = SSL_do_handshake(s->conn);
    if (r == 1) {
      s->handshake_done = true;
      s->peerCN = peer_cn(s->conn);
    } else {
      int e = SSL_get_error(s->conn, r);
      if (!(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)) {
        std::string errs = openssl_errs_all();
        s->lastError = "handshake init failed";
        if (!errs.empty()) s->lastError += ": " + errs;
      }
    }

    quic_drain_app_out(s);
  }

  napi_value sessionObj, cons;
  napi_get_reference_value(env, QUICSession_ctor_ref, &cons);
  napi_new_instance(env, cons, 0, nullptr, &sessionObj);

  napi_wrap(env, sessionObj, s,
    [](napi_env, void* data, void*) { delete (QUICSession*)data; },
    nullptr, nullptr
  );
  return sessionObj;
}

/* ============================================================
   QUICSession JS class
   ============================================================ */

static napi_value QUICSession_ctor(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
  return jsthis;
}

static napi_value QUICSession_feedDatagram(napi_env env, napi_callback_info info) {
  size_t argc=1; napi_value args[1]; napi_value jsthis;
  napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);

  if (argc < 1 || !is_buffer(env, args[0])) {
    throw_err(env, "feedDatagram(Buffer) required");
    return nullptr;
  }

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s || !s->net_app) {
    throw_err(env, "bad this");
    return nullptr;
  }

  uint8_t* data=nullptr; size_t len=0;
  napi_get_buffer_info(env, args[0], (void**)&data, &len);

  int w = BIO_write(s->net_app, data, (int)len);
  if (w <= 0 && !BIO_should_retry(s->net_app)) {
    if (s->lastError.empty()) {
      std::string errs = openssl_errs_all();
      s->lastError = "BIO_write(inbound) failed";
      if (!errs.empty()) s->lastError += ": " + errs;
    }
  }

  napi_value u; napi_get_undefined(env, &u); return u;
}

static napi_value QUICSession_pump(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) {
    throw_err(env, "bad this");
    return nullptr;
  }

  quic_pump(s);

  napi_value u; napi_get_undefined(env, &u); return u;
}

static napi_value QUICSession_drainOutgoing(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) { throw_err(env, "bad this"); return nullptr; }

  napi_value arr;
  napi_create_array_with_length(env, s->outgoing.size(), &arr);
  for (size_t i=0;i<s->outgoing.size();i++) {
    auto& v = s->outgoing[i];
    napi_set_element(env, arr, (uint32_t)i, make_buffer_copy(env, v.data(), v.size()));
  }
  s->outgoing.clear();
  return arr;
}

static napi_value QUICSession_takePlaintext(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) { throw_err(env, "bad this"); return nullptr; }

  napi_value arr;
  napi_create_array_with_length(env, s->incoming.size(), &arr);
  for (size_t i=0;i<s->incoming.size();i++) {
    auto& v = s->incoming[i];
    napi_set_element(env, arr, (uint32_t)i, make_buffer_copy(env, v.data(), v.size()));
  }
  s->incoming.clear();
  return arr;
}

static napi_value QUICSession_isHandshakeDone(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) { throw_err(env, "bad this"); return nullptr; }

  return make_bool(env, s->handshake_done);
}

static napi_value QUICSession_sendPlaintext(napi_env env, napi_callback_info info) {
  size_t argc=1; napi_value args[1]; napi_value jsthis;
  napi_get_cb_info(env, info, &argc, args, &jsthis, nullptr);

  if (argc < 1 || !is_buffer(env, args[0])) {
    throw_err(env, "sendPlaintext(Buffer) required");
    return nullptr;
  }

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) { throw_err(env, "bad this"); return nullptr; }

  if (!s->handshake_done) {
    throw_err(env, "sendPlaintext: handshake not done");
    return nullptr;
  }

  quic_try_make_stream(s);
  if (!s->stream_ready || !s->stream) {
    throw_err(env, "sendPlaintext: stream not ready yet");
    return nullptr;
  }

  uint8_t* data=nullptr; size_t len=0;
  napi_get_buffer_info(env, args[0], (void**)&data, &len);

  size_t nw = 0;
  int wr = SSL_write_ex(s->stream, data, len, &nw);
  if (wr != 1) {
    int e = SSL_get_error(s->stream, wr);
    if (!(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)) {
      if (s->lastError.empty()) {
        std::string errs = openssl_errs_all();
        s->lastError = "ssl_write_ex failed";
        if (!errs.empty()) s->lastError += ": " + errs;
      }
      std::string msg = "sendPlaintext failed";
      std::string errs = openssl_errs_all();
      if (!errs.empty()) msg += ": " + errs;
      msg += " | " + join_diag();
      throw_err_str(env, msg);
      return nullptr;
    }
  }

  quic_drain_app_out(s);
  return make_u32(env, (uint32_t)nw);
}

static napi_value QUICSession_getPeerCN(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) { throw_err(env, "bad this"); return nullptr; }
  return make_string(env, s->peerCN);
}

static napi_value QUICSession_getLastError(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) { throw_err(env, "bad this"); return nullptr; }
  return make_string(env, s->lastError);
}

static napi_value QUICSession_isServer(napi_env env, napi_callback_info info) {
  napi_value jsthis;
  napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);

  QUICSession* s=nullptr;
  napi_unwrap(env, jsthis, (void**)&s);
  if (!s) { throw_err(env, "bad this"); return nullptr; }
  return make_bool(env, s->is_server);
}

/* ============================================================
   Exports: opensslRuntime / opensslDiagnose
   ============================================================ */

static napi_value OpenSSL_runtime(napi_env env, napi_callback_info) {
  napi_value o, v, n;
  napi_create_object(env, &o);

  const char* ver = OpenSSL_version(OPENSSL_VERSION);
  napi_create_string_utf8(env, ver, NAPI_AUTO_LENGTH, &v);
  napi_set_named_property(env, o, "version", v);

  uint64_t num = (uint64_t)OpenSSL_version_num();
  napi_create_bigint_uint64(env, num, &n);
  napi_set_named_property(env, o, "versionNum", n);

  return o;
}

static napi_value OpenSSL_diagnose(napi_env env, napi_callback_info) {
  napi_value o;
  napi_create_object(env, &o);

  auto setS = [&](const char* k, const std::string& v){
    napi_value x; napi_create_string_utf8(env, v.c_str(), v.size(), &x);
    napi_set_named_property(env, o, k, x);
  };
  auto setB = [&](const char* k, bool b){
    napi_value x; napi_get_boolean(env, b, &x);
    napi_set_named_property(env, o, k, x);
  };

  setS("version", OpenSSL_version(OPENSSL_VERSION));
  setS("openssldir", OpenSSL_version(OPENSSL_DIR));
  setS("OPENSSL_MODULES", getenv_str("OPENSSL_MODULES"));
  setS("OPENSSL_CONF", getenv_str("OPENSSL_CONF"));
  setS("init_diag", g_init_diag);

#ifdef _WIN32
  setS("libcrypto_loaded_dir", win_libcrypto_dir());
  setS("libssl_loaded_dir", win_libssl_dir());
#endif

  setB("provider_default_loaded", g_prov_default != nullptr);
  setB("provider_legacy_loaded", g_prov_legacy != nullptr);

  setB("has_quic_server_method", OSSL_QUIC_server_method() != nullptr);
  setB("has_quic_client_method", OSSL_QUIC_client_method() != nullptr);

  return o;
}

/* ============================================================
   Module init
   ============================================================ */

static napi_value init(napi_env env, napi_value exports) {
  std::call_once(g_ssl_init_once, openssl_init_once);

  // functions
  {
    napi_property_descriptor fns[] = {
      { "opensslRuntime",  0, OpenSSL_runtime,  0, 0, 0, napi_default, 0 },
      { "opensslDiagnose", 0, OpenSSL_diagnose, 0, 0, 0, napi_default, 0 }
    };
    napi_define_properties(env, exports, 2, fns);
  }

  // QUICContext
  napi_value ctxCons;
  {
    napi_property_descriptor props[] = {
      { "createSession", 0, QUICContext_createSession, 0, 0, 0, napi_default, 0 }
    };
    napi_define_class(env, "QUICContext", NAPI_AUTO_LENGTH, QUICContext_ctor, nullptr,
                      (uint32_t)(sizeof(props)/sizeof(props[0])), props, &ctxCons);
    napi_create_reference(env, ctxCons, 1, &QUICContext_ctor_ref);
    napi_set_named_property(env, exports, "QUICContext", ctxCons);
  }

  // QUICSession
  napi_value sesCons;
  {
    napi_property_descriptor props[] = {
      { "feedDatagram",    0, QUICSession_feedDatagram,    0, 0, 0, napi_default, 0 },
      { "pump",            0, QUICSession_pump,            0, 0, 0, napi_default, 0 },
      { "drainOutgoing",   0, QUICSession_drainOutgoing,   0, 0, 0, napi_default, 0 },
      { "takePlaintext",   0, QUICSession_takePlaintext,   0, 0, 0, napi_default, 0 },
      { "isHandshakeDone", 0, QUICSession_isHandshakeDone, 0, 0, 0, napi_default, 0 },
      { "sendPlaintext",   0, QUICSession_sendPlaintext,   0, 0, 0, napi_default, 0 },
      { "getLastError",    0, QUICSession_getLastError,    0, 0, 0, napi_default, 0 },
      { "isServer",        0, QUICSession_isServer,        0, 0, 0, napi_default, 0 },

      // property getter
      { "peerCN",          0, 0, 0, QUICSession_getPeerCN, 0, napi_default, 0 }
    };

    napi_define_class(env, "QUICSession", NAPI_AUTO_LENGTH, QUICSession_ctor, nullptr,
                      (uint32_t)(sizeof(props)/sizeof(props[0])), props, &sesCons);
    napi_create_reference(env, sesCons, 1, &QUICSession_ctor_ref);
    napi_set_named_property(env, exports, "QUICSession", sesCons);
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
