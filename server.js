'use strict';
/*
 * Nimbus: a small session-based web proxy. One dependency (ws). Needs Node 18.14+.
 *
 *   npm install
 *   node server.js
 *
 * Environment variables:
 *   PORT           default 8080
 *   HOST           default 127.0.0.1 (local only). Use 0.0.0.0 to serve other devices.
 *   PASSWORD       optional. If set, creating a session requires it.
 *   ALLOW_PRIVATE  set to 1 to let the proxy reach localhost / LAN addresses (off by default).
 *   SEARCH_URL     search engine used when you type words instead of an address.
 *                  Default https://html.duckduckgo.com/html/?q=   (your words are added on the end)
 *   DEBUG          set to 1 to log each request (host, path, status) and WebSocket events. Off by default.
 */

const http = require('http');
const dns = require('dns').promises;
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const { WebSocketServer, WebSocket } = require('ws');

// Prefer IPv4 and fall back between address families. Avoids connect timeouts on networks with broken IPv6.
try { require('dns').setDefaultResultOrder('ipv4first'); } catch {}
try { if (net.setDefaultAutoSelectFamily) net.setDefaultAutoSelectFamily(true); } catch {}

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const PASSWORD = process.env.PASSWORD || '';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';
const DEBUG = process.env.DEBUG === '1';
const SEARCH_URL = process.env.SEARCH_URL || 'https://html.duckduckgo.com/html/?q=';
const log = (...a) => { if (DEBUG) console.log(new Date().toISOString().slice(11, 19), ...a); };
const SESSION_TTL = 3 * 24 * 60 * 60 * 1000; // idle sessions are deleted after 3 days
const MAX_BODY = 50 * 1024 * 1024;

const SID = '[0-9a-f]{24}';
const PROXY_RE = new RegExp(`^/p/(${SID})/(https?):/+(.*)$`);
const COOKIE_RE = new RegExp(`^/p/(${SID})/__cookie\\?u=([^&]+)$`);

/* ------------------------------------------------------------------ sessions */

const sessions = new Map(); // id -> { jar: [], last: ms }

function createSession() {
  const id = crypto.randomBytes(12).toString('hex');
  sessions.set(id, { jar: [], last: Date.now() });
  return id;
}

function getSession(id) {
  const s = sessions.get(id);
  if (s) s.last = Date.now();
  return s;
}

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) if (now - s.last > SESSION_TTL) sessions.delete(id);
}, 60 * 60 * 1000).unref();

/* ------------------------------------------------------------------- cookies */

function hostMatches(cookie, hostname) {
  if (cookie.hostOnly) return hostname === cookie.domain;
  return hostname === cookie.domain || hostname.endsWith('.' + cookie.domain);
}

function parseSetCookie(str, url) {
  const parts = String(str).split(';').map((s) => s.trim());
  const eq = parts[0].indexOf('=');
  if (eq < 1) return null;
  const c = {
    name: parts[0].slice(0, eq),
    value: parts[0].slice(eq + 1),
    domain: url.hostname,
    hostOnly: true,
    path: null,
    expires: null,
    secure: false,
    httpOnly: false,
  };
  for (const p of parts.slice(1)) {
    const i = p.indexOf('=');
    const k = (i < 0 ? p : p.slice(0, i)).toLowerCase();
    const v = i < 0 ? '' : p.slice(i + 1);
    if (k === 'domain' && v) {
      c.domain = v.replace(/^\./, '').toLowerCase();
      c.hostOnly = false;
    } else if (k === 'path' && v.startsWith('/')) c.path = v;
    else if (k === 'expires') {
      const t = Date.parse(v);
      if (!isNaN(t)) c.expires = t;
    } else if (k === 'max-age') {
      const n = parseInt(v, 10);
      if (!isNaN(n)) c.expires = Date.now() + n * 1000;
    } else if (k === 'secure') c.secure = true;
    else if (k === 'httponly') c.httpOnly = true;
  }
  if (!c.path) {
    const d = url.pathname;
    c.path = d.slice(0, d.lastIndexOf('/')) || '/';
  }
  if (!c.hostOnly && !(url.hostname === c.domain || url.hostname.endsWith('.' + c.domain))) return null;
  return c;
}

function storeCookie(sess, c) {
  sess.jar = sess.jar.filter((x) => !(x.name === c.name && x.domain === c.domain && x.path === c.path));
  if (c.expires !== null && c.expires <= Date.now()) return;
  sess.jar.push(c);
}

function cookiesFor(sess, url, includeHttpOnly = true) {
  const now = Date.now();
  sess.jar = sess.jar.filter((c) => c.expires === null || c.expires > now);
  return sess.jar
    .filter((c) => {
      if (!hostMatches(c, url.hostname)) return false;
      if (c.secure && url.protocol !== 'https:') return false;
      if (!includeHttpOnly && c.httpOnly) return false;
      const p = url.pathname;
      const cp = c.path.endsWith('/') ? c.path : c.path + '/';
      return p === c.path || p.startsWith(cp);
    })
    .sort((a, b) => b.path.length - a.path.length)
    .map((c) => c.name + '=' + c.value)
    .join('; ');
}

/* ------------------------------------------------------------ address safety */

function isPrivateIp(ip) {
  const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (m) {
    const x = parseInt(m[1], 16);
    const y = parseInt(m[2], 16);
    ip = `${x >> 8}.${x & 255}.${y >> 8}.${y & 255}`;
  }
  if (ip.toLowerCase().startsWith('::ffff:')) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::' || l === '::1' || /^f[cd]/.test(l) || /^fe[89ab]/.test(l);
  }
  return true;
}

async function hostProblem(hostname) {
  if (ALLOW_PRIVATE) return null;
  const h = hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(h)) return isPrivateIp(h) ? `${h} is a private address` : null;
  if (h === 'localhost' || h.endsWith('.localhost')) return `${h} is a private address`;
  let addrs;
  try {
    addrs = await dns.lookup(h, { all: true });
  } catch {
    return `${h} could not be looked up (DNS failed)`;
  }
  const bad = addrs.find((a) => isPrivateIp(a.address));
  return bad ? `${h} resolves to the private address ${bad.address} (a network filter may be redirecting it)` : null;
}

// Reads the first few bytes of a response without consuming the real one (used only for DEBUG logs).
async function peek(resp) {
  const reader = resp.clone().body.getReader();
  const { value } = await reader.read();
  reader.cancel().catch(() => {});
  return Buffer.from(value || []).toString('utf8', 0, 200).replace(/\s+/g, ' ');
}

/* ---------------------------------------------------------------- rewriting */

const decodeAmp = (s) => s.replace(/&amp;/g, '&');
const esc = (s) => s.replace(/&(?!#?\w+;)/g, '&amp;').replace(/"/g, '&quot;');

function proxify(sid, base, value) {
  if (value == null) return value;
  const t = String(value).trim();
  if (!t || t[0] === '#' || /^(data|blob|javascript|mailto|tel|about):/i.test(t)) return value;
  try {
    const abs = new URL(decodeAmp(t), base);
    if (abs.protocol !== 'http:' && abs.protocol !== 'https:') return value;
    return `/p/${sid}/${abs.href}`;
  } catch {
    return value;
  }
}

function rewriteCss(css, sid, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => `url(${q}${proxify(sid, base, u)}${q})`)
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => `@import ${q}${proxify(sid, base, u)}${q}`);
}

function rewriteHtml(html, sid, pageUrl, cookieStr, inject) {
  let base = pageUrl;
  const bm = /<base\s[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/i.exec(html);
  if (bm) {
    try {
      base = new URL(decodeAmp(bm[1] ?? bm[2] ?? bm[3]), pageUrl).href;
    } catch {}
    html = html.replace(bm[0], () => '');
  }

  html = html
    // drop things that would block the proxy or leak the real address
    .replace(/<meta\s[^>]*http-equiv\s*=\s*["']?(?:content-security-policy|x-frame-options)["']?[^>]*>/gi, '')
    .replace(/<meta\s[^>]*name\s*=\s*["']?referrer["']?[^>]*>/gi, '')
    .replace(/\sintegrity\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '')
    // <meta http-equiv="refresh" content="0; url=...">
    .replace(
      /(<meta\s[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*?url=)([^"']*)/gi,
      (m, a, u) => a + proxify(sid, base, u)
    )
    // URL attributes
    .replace(
      /(\s(?:xlink:)?(?:href|src|action|formaction|poster|data-src|data-href)\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/gi,
      (m, pre, a, b, c) => {
        const v = a ?? b ?? c;
        const p = proxify(sid, base, v);
        return p === v ? m : pre + '"' + esc(p) + '"';
      }
    )
    // srcset
    .replace(/(\s(?:srcset|data-srcset)\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi, (m, pre, a, b) => {
      const out = (a ?? b)
        .split(',')
        .map((part) => {
          const [u, ...d] = part.trim().split(/\s+/);
          return u ? [proxify(sid, base, u), ...d].join(' ') : '';
        })
        .join(', ');
      return pre + '"' + esc(out) + '"';
    })
    // CSS in <style> blocks and style="" attributes
    .replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, css, c) => a + rewriteCss(css, sid, base) + c)
    .replace(/(\sstyle\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi, (m, pre, a, b) => {
      const v = a ?? b;
      const r = rewriteCss(v, sid, base);
      return r === v ? m : pre + '"' + esc(r) + '"';
    });

  if (inject) {
    const script = clientScript(sid, pageUrl, cookieStr);
    let done = false;
    html = html.replace(/<head[^>]*>/i, (m) => ((done = true), m + script));
    if (!done) html = html.replace(/<html[^>]*>/i, (m) => ((done = true), m + script));
    if (!done) html = script + html;
  }
  return html;
}

/* --------------------------------------------- script injected into each page */

// This function is serialized and runs in the browser, inside the proxied page.
function clientMain(cfg) {
  var P = '/p/' + cfg.sid + '/';
  var O = location.origin;
  var real = new URL(cfg.url);
  var sendBeacon = navigator.sendBeacon ? navigator.sendBeacon.bind(navigator) : null;

  function toReal(u) {
    var s = String(u).trim();
    if (s.indexOf(O + P) === 0) s = s.slice(O.length);
    if (s.indexOf(P) === 0) return s.slice(P.length);
    if (s.indexOf(O) === 0) s = s.slice(O.length) || '/';
    return new URL(s, real.href).href;
  }
  function toProxy(u) {
    if (u == null) return u;
    var t = String(u).trim();
    if (!t || t.charAt(0) === '#' || /^(data|blob|javascript|mailto|tel|about):/i.test(t)) return u;
    if (t.indexOf(P) === 0 || t.indexOf(O + P) === 0) return u;
    try {
      var r = toReal(t);
      return /^https?:/i.test(r) ? P + r : u;
    } catch (e) {
      return u;
    }
  }

  // Network calls made by the page's own scripts
  var _fetch = window.fetch;
  window.fetch = function (input, init) {
    if (typeof input === 'string' || input instanceof URL) input = toProxy(input);
    else if (input && input.url) input = new Request(toProxy(input.url), input);
    return _fetch.call(this, input, init);
  };
  var _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) {
    arguments[1] = toProxy(u);
    return _open.apply(this, arguments);
  };
  if (sendBeacon) navigator.sendBeacon = function (u, d) { return sendBeacon(toProxy(u), d); };
  var _wo = window.open;
  window.open = function (u) {
    if (u) arguments[0] = toProxy(u);
    return _wo.apply(this, arguments);
  };
  ['pushState', 'replaceState'].forEach(function (k) {
    var orig = history[k];
    history[k] = function (s, t, u) {
      if (u != null) {
        try { real = new URL(toReal(u)); } catch (e) {}
        u = toProxy(u);
      }
      return orig.call(this, s, t, u);
    };
  });

  // Elements the page creates or edits with scripts
  [[HTMLImageElement, 'src'], [HTMLScriptElement, 'src'], [HTMLIFrameElement, 'src'],
   [HTMLSourceElement, 'src'], [HTMLMediaElement, 'src'], [HTMLLinkElement, 'href'],
   [HTMLAnchorElement, 'href'], [HTMLFormElement, 'action']].forEach(function (p) {
    var d = Object.getOwnPropertyDescriptor(p[0].prototype, p[1]);
    if (d && d.set) {
      Object.defineProperty(p[0].prototype, p[1], {
        get: d.get, enumerable: d.enumerable, configurable: true,
        set: function (v) { d.set.call(this, toProxy(v)); },
      });
    }
  });
  var _sa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (k, v) {
    if (/^(src|href|action|poster)$/i.test(k) && typeof v === 'string') v = toProxy(v);
    return _sa.call(this, k, v);
  };

  // document.cookie reads from a copy of this session's cookies and writes back to the server
  var jar = {};
  (cfg.cookies || '').split('; ').forEach(function (c) {
    var i = c.indexOf('=');
    if (i > 0) jar[c.slice(0, i)] = c.slice(i + 1);
  });
  Object.defineProperty(document, 'cookie', {
    configurable: true,
    get: function () {
      return Object.keys(jar).map(function (k) { return k + '=' + jar[k]; }).join('; ');
    },
    set: function (v) {
      v = String(v);
      var first = v.split(';')[0];
      var i = first.indexOf('=');
      if (i < 1) return;
      var k = first.slice(0, i).trim();
      var ma = /(?:^|;)\s*max-age=(-?\d+)/i.exec(v);
      var ex = /(?:^|;)\s*expires=([^;]+)/i.exec(v);
      var gone = (ma && +ma[1] <= 0) || (ex && Date.parse(ex[1]) < Date.now());
      if (gone) delete jar[k]; else jar[k] = first.slice(i + 1);
      if (sendBeacon) sendBeacon(P + '__cookie?u=' + encodeURIComponent(real.href), v);
    },
  });

  // WebSockets go through the server too: /_ws/<session>?u=<real ws address>
  var NativeWS = window.WebSocket;
  function ProxyWS(url, protocols) {
    var t = new URL(String(url), real.href);
    if (t.protocol === 'http:') t.protocol = 'ws:';
    else if (t.protocol === 'https:') t.protocol = 'wss:';
    var via = (location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + location.host +
      '/_ws/' + cfg.sid + '?u=' + encodeURIComponent(t.href);
    return protocols === undefined ? new NativeWS(via) : new NativeWS(via, protocols);
  }
  ProxyWS.prototype = NativeWS.prototype;
  ProxyWS.CONNECTING = 0; ProxyWS.OPEN = 1; ProxyWS.CLOSING = 2; ProxyWS.CLOSED = 3;
  window.WebSocket = ProxyWS;

  // Service workers are not supported. Blocking them stops pages from bypassing the proxy.
  try {
    if (navigator.serviceWorker) {
      navigator.serviceWorker.register = function () { return Promise.reject(new Error('Blocked by proxy')); };
    }
  } catch (e) {}

  // Small address bar in the corner of every page
  function normalize(v) {
    v = v.trim();
    if (!v) return '';
    if (/^https?:\/\//i.test(v)) return v;
    if (/^[^\s\/]+\.[a-z]{2,}([\/:?#].*)?$/i.test(v) || /^localhost(:\d+)?/i.test(v)) return 'https://' + v;
    return cfg.search + encodeURIComponent(v);
  }
  if (window.top === window) {
    document.addEventListener('DOMContentLoaded', function () {
      var host = document.createElement('div');
      host.style.cssText = 'all:initial;position:fixed;left:12px;bottom:12px;z-index:2147483647';
      var root = host.attachShadow({ mode: 'open' });
      root.innerHTML =
        '<style>' +
        '*{box-sizing:border-box;font:13px/1 ui-rounded,system-ui,sans-serif}' +
        '.p{display:flex;gap:6px;align-items:center;color:#f5f2ff;padding:5px;border-radius:999px;' +
        'background:rgba(16,14,48,.78);-webkit-backdrop-filter:blur(16px) saturate(150%);backdrop-filter:blur(16px) saturate(150%);' +
        'border:1px solid rgba(255,255,255,.22);box-shadow:0 10px 30px rgba(4,6,30,.45),inset 0 1px 0 rgba(255,255,255,.18)}' +
        'button{border:0;border-radius:999px;height:30px;padding:0 14px;cursor:pointer;font-weight:700;color:#0a0d2b;' +
        'background:linear-gradient(135deg,#7df3ff,#b18cff)}' +
        'button:hover{filter:brightness(1.1)}' +
        '.t{display:flex;align-items:center;gap:7px;background:transparent;color:#f5f2ff;padding:0 10px 0 8px}' +
        '.t:hover{filter:none;background:rgba(255,255,255,.1)}' +
        '.h{background:rgba(255,255,255,.14);color:#f5f2ff}' +
        'input,.go,.h{display:none}' +
        'input{width:min(60vw,380px);height:30px;border:0;border-radius:999px;padding:0 14px;background:rgba(255,255,255,.94);color:#0d1b3d;outline:none}' +
        'input:focus{box-shadow:0 0 0 3px rgba(125,243,255,.5)}' +
        '.o input,.o .go,.o .h{display:block}' +
        '</style>' +
        '<div class="p"><button class="t" title="Address bar">' +
        '<svg width="20" height="14" viewBox="0 0 64 44" aria-hidden="true"><path fill="#c9c3ff" d="M18 40C9.2 40 4 34.4 4 28.2c0-5.2 3.7-9.6 8.8-10.6C14.4 10.4 20.6 5 28 5c6.6 0 12 3.9 14.3 9.5.9-.3 2-.5 3.2-.5C52 14 58 19 58 26.5 58 33.7 53 40 45.5 40z"/></svg>nimbus</button>' +
        '<input placeholder="Search or enter a web address" spellcheck="false">' +
        '<button class="go">Go</button><button class="h">Home</button></div>';
      var box = root.querySelector('.p');
      var input = root.querySelector('input');
      function go() {
        var u = normalize(input.value);
        if (u) location.href = P + u;
      }
      root.querySelector('.t').onclick = function () {
        box.classList.toggle('o');
        input.value = real.href;
        if (box.classList.contains('o')) input.select();
      };
      root.querySelector('.go').onclick = go;
      root.querySelector('.h').onclick = function () { location.href = '/'; };
      input.onkeydown = function (e) {
        e.stopPropagation();
        if (e.key === 'Enter') go();
      };
      input.onkeyup = input.onkeypress = function (e) { e.stopPropagation(); };
      document.documentElement.appendChild(host);
    });
  }
}

const CLIENT_SRC = clientMain.toString();

function clientScript(sid, url, cookies) {
  const cfg = JSON.stringify({ sid, url, cookies, search: SEARCH_URL }).replace(/</g, '\\u003c');
  return `<script>(${CLIENT_SRC})(${cfg});</script>`;
}

/* ------------------------------------------------------------------ helpers */

function send(res, status, text, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' });
  res.end(text);
}

function sendJson(res, status, obj) {
  send(res, status, JSON.stringify(obj), 'application/json');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > MAX_BODY) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// If the request came from a proxied page, work out which real page that was.
function proxyRef(req) {
  const r = req.headers.referer;
  if (!r) return null;
  try {
    const u = new URL(r);
    const m = new RegExp(`^/p/(${SID})/`).exec(u.pathname);
    if (!m) return null;
    const rest = (u.pathname + u.search).slice(m[0].length).replace(/^(https?):\/+/, '$1://');
    const full = new URL(rest);
    return { sid: m[1], full: full.href, origin: full.origin };
  } catch {
    return null;
  }
}

const DROP = new Set([
  'content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'content-encoding', 'content-length', 'transfer-encoding', 'connection', 'keep-alive',
  'set-cookie', 'strict-transport-security', 'public-key-pins', 'report-to', 'nel', 'alt-svc',
  'link', 'location', 'content-location', 'refresh', 'cross-origin-opener-policy',
  'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'permissions-policy',
  'referrer-policy',
]);

/* ------------------------------------------------------------------ site fixes */

// Small edits to a site's own JavaScript, for sites that check which address they are running on.
// If an edit stops matching (the site changed its code), turn on DEBUG and look for "SITE PATCH".
const SITE_PATCHES = [
  {
    // Pokemon Showdown's client only connects to its normal game server when the page is on
    // play.pokemonshowdown.com. On any other address it asks the login server for a server config
    // for that address. For 127.0.0.1 that config points at your own computer, so the client never
    // reaches the real game server. This makes it take the normal path instead.
    name: 'showdown-origin-check',
    host: /(^|\.)pokemonshowdown\.com$/,
    file: /\/js\/oldclient\/storage\.js$/,
    edit: (js) => js.replace(/location\.protocol\s*\+\s*(['"])\/\/\1\s*\+\s*location\.hostname\s*===\s*Storage\.origin/, 'true'),
  },
];

/* -------------------------------------------------------------- proxy handler */

async function handleProxy(req, res, sid, targetStr, ref) {
  const sess = getSession(sid);
  if (!sess) return send(res, 410, 'This session was not found or has expired. Go to the start page and create a new one.');

  let target;
  try {
    target = new URL(targetStr);
  } catch {
    return send(res, 400, 'That is not a valid address.');
  }
  const problem = await hostProblem(target.hostname);
  if (problem) {
    log('BLOCKED BY NIMBUS:', problem);
    return send(res, 403, 'Blocked by Nimbus: ' + problem + '.');
  }

  const method = req.method;
  const hasBody = method !== 'GET' && method !== 'HEAD';
  const body = hasBody ? await readBody(req) : undefined;

  // Only forward a fixed set of headers, so nothing identifying leaks through by accident.
  const headers = {};
  for (const k of ['user-agent', 'accept', 'accept-language', 'content-type', 'range', 'if-none-match', 'if-modified-since', 'x-requested-with']) {
    if (req.headers[k]) headers[k] = req.headers[k];
  }
  const cookie = cookiesFor(sess, target);
  if (cookie) headers.cookie = cookie;
  if (ref) {
    headers.referer = ref.full;
    if (hasBody || req.headers.origin) headers.origin = ref.origin;
  }

  let up;
  try {
    up = await fetch(target, { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(30000) });
  } catch (e) {
    const code = (e.cause && e.cause.code) || e.name || e.message;
    log('FETCH FAILED', method, target.host + target.pathname, code);
    const why = {
      UND_ERR_CONNECT_TIMEOUT: 'the connection timed out. That site may be blocked from the network this server is on, or it may be down.',
      TimeoutError: 'it took longer than 30 seconds to answer.',
      ENOTFOUND: 'that address could not be looked up.',
      ECONNREFUSED: 'the connection was refused.',
    }[code] || code;
    return send(res, 502, `Could not reach ${target.host}: ${why}`);
  }
  log(method, target.host + target.pathname.slice(0, 70), up.status, up.headers.get('content-type') || '');
  if (DEBUG && [401, 403, 429, 503].includes(up.status) && up.body) {
    peek(up).then((t) => log('   the site said:', t)).catch(() => {});
  }

  for (const sc of up.headers.getSetCookie ? up.headers.getSetCookie() : []) {
    const c = parseSetCookie(sc, target);
    if (c) storeCookie(sess, c);
  }

  const out = {};
  for (const [k, v] of up.headers) if (!DROP.has(k)) out[k] = v;
  out['referrer-policy'] = 'same-origin';

  const loc = up.headers.get('location');
  if (loc && up.status >= 300 && up.status < 400) out.location = proxify(sid, target.href, loc);

  if (method === 'HEAD' || !up.body || (up.status >= 300 && up.status < 400) || up.status === 204 || up.status === 304) {
    res.writeHead(up.status, out);
    return res.end();
  }

  const ct = up.headers.get('content-type') || '';
  const isHtml = /text\/html|application\/xhtml\+xml/i.test(ct);
  const isCss = /text\/css/i.test(ct);

  if (isHtml || isCss) {
    const buf = Buffer.from(await up.arrayBuffer());
    let cs = (/charset\s*=\s*["']?([\w-]+)/i.exec(ct) || [])[1];
    if (!cs && isHtml) cs = (/<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(buf.subarray(0, 4096).toString('latin1')) || [])[1];
    let text;
    try {
      text = new TextDecoder(cs || 'utf-8').decode(buf);
    } catch {
      text = buf.toString('utf8');
    }
    if (isHtml) {
      // Page loads get the client script. Background requests (fetch/XHR) only get their links rewritten.
      const dest = req.headers['sec-fetch-dest'];
      const inject = !dest || ['document', 'iframe', 'frame', 'embed', 'object'].includes(dest);
      text = rewriteHtml(text, sid, target.href, cookiesFor(sess, target, false), inject);
    } else {
      text = rewriteCss(text, sid, target.href);
    }
    const data = Buffer.from(text, 'utf8');
    out['content-type'] = (isHtml ? 'text/html' : 'text/css') + '; charset=utf-8';
    out['content-length'] = data.length;
    res.writeHead(up.status, out);
    return res.end(data);
  }

  const patch = up.status === 200 && SITE_PATCHES.find((x) => x.host.test(target.hostname) && x.file.test(target.pathname));
  if (patch) {
    const original = Buffer.from(await up.arrayBuffer()).toString('utf8');
    const edited = patch.edit(original);
    log(edited === original ? 'SITE PATCH DID NOT MATCH:' : 'site patch applied:', patch.name);
    const data = Buffer.from(edited, 'utf8');
    out['content-type'] = 'text/javascript; charset=utf-8';
    out['content-length'] = data.length;
    res.writeHead(up.status, out);
    return res.end(data);
  }

  // Everything else (images, video, JS, fonts, downloads) is streamed through unchanged.
  if (!up.headers.has('content-encoding') && up.headers.has('content-length')) {
    out['content-length'] = up.headers.get('content-length');
  }
  res.writeHead(up.status, out);
  const stream = Readable.fromWeb(up.body);
  res.on('close', () => stream.destroy());
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

/* ----------------------------------------------------------------------- API */

async function handleApi(req, res) {
  const url = new URL(req.url, 'http://x');

  if (req.method === 'GET' && url.pathname === '/_px/session') {
    return sendJson(res, 200, { exists: sessions.has(url.searchParams.get('id') || '') });
  }
  if (req.method === 'POST' && url.pathname === '/_px/session') {
    let data = {};
    try { data = JSON.parse((await readBody(req)).toString() || '{}'); } catch {}
    if (PASSWORD && data.password !== PASSWORD) return sendJson(res, 401, { error: 'password required' });
    return sendJson(res, 200, { id: createSession() });
  }
  if (req.method === 'POST' && url.pathname === '/_px/session/delete') {
    let data = {};
    try { data = JSON.parse((await readBody(req)).toString() || '{}'); } catch {}
    sessions.delete(data.id);
    return sendJson(res, 200, { ok: true });
  }
  send(res, 404, 'Not found');
}

/* -------------------------------------------------------------------- server */

const INDEX = Buffer.from(
  fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8')
    .replace('__SEARCH_URL__', () => SEARCH_URL.replace(/\\/g, '\\\\').replace(/'/g, "\\'"))
);

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url;
    let m;

    if (req.method === 'POST' && (m = COOKIE_RE.exec(url))) {
      const sess = getSession(m[1]);
      if (sess) {
        const c = parseSetCookie((await readBody(req)).toString(), new URL(decodeURIComponent(m[2])));
        if (c) {
          c.httpOnly = false;
          storeCookie(sess, c);
        }
      }
      res.writeHead(204);
      return res.end();
    }

    if ((m = PROXY_RE.exec(url))) return await handleProxy(req, res, m[1], `${m[2]}://${m[3]}`, proxyRef(req));

    if (url.startsWith('/_px/')) return await handleApi(req, res);

    // A proxied page asked for a path on our own origin (for example /api/data).
    // Send it to the same path on the site that page came from.
    const ref = proxyRef(req);
    if (ref) {
      res.writeHead(307, { location: `/p/${ref.sid}/${ref.origin}${url}`, 'cache-control': 'no-store' });
      return res.end();
    }

    if (url === '/' || url.startsWith('/?') || url === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(INDEX);
    }
    send(res, 404, 'Not found');
  } catch (e) {
    if (!res.headersSent) send(res, 500, 'Proxy error: ' + e.message);
    else res.destroy();
  }
});

/* ------------------------------------------------------------------ WebSockets */

const WS_RE = new RegExp(`^/_ws/(${SID})\\?u=(.+)$`);
const wss = new WebSocketServer({
  noServer: true,
  handleProtocols: (protocols, req) => (req._upstreamProtocol && protocols.has(req._upstreamProtocol) ? req._upstreamProtocol : false),
});

function rejectUpgrade(socket, code, text) {
  socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  socket.destroy();
}

function closeSafe(ws, code, reason) {
  const ok = code >= 1000 && code <= 4999 && ![1004, 1005, 1006, 1015].includes(code);
  try {
    ws.close(ok ? code : 1000, reason);
  } catch {
    ws.terminate();
  }
}

server.on('upgrade', async (req, socket, head) => {
  socket.on('error', () => {});
  const m = WS_RE.exec(req.url);
  if (!m) return rejectUpgrade(socket, 400, 'Bad Request');
  const sess = getSession(m[1]);
  if (!sess) return rejectUpgrade(socket, 410, 'Gone');

  let target;
  try {
    target = new URL(decodeURIComponent(m[2]));
  } catch {
    return rejectUpgrade(socket, 400, 'Bad Request');
  }
  if (target.protocol !== 'ws:' && target.protocol !== 'wss:') return rejectUpgrade(socket, 400, 'Bad Request');
  const problem = await hostProblem(target.hostname);
  if (problem) {
    log('WS BLOCKED BY NIMBUS:', problem);
    return rejectUpgrade(socket, 403, 'Forbidden');
  }
  log('WS connecting', target.host + target.pathname.slice(0, 70));

  const httpUrl = new URL(target.href);
  httpUrl.protocol = target.protocol === 'wss:' ? 'https:' : 'http:';
  const headers = { origin: httpUrl.origin };
  if (req.headers['user-agent']) headers['user-agent'] = req.headers['user-agent'];
  const ck = cookiesFor(sess, httpUrl);
  if (ck) headers.cookie = ck;
  const protocols = (req.headers['sec-websocket-protocol'] || '').split(',').map((x) => x.trim()).filter(Boolean);

  const upstream = new WebSocket(target.href, protocols, { headers, handshakeTimeout: 15000 });
  upstream.on('upgrade', (r) => {
    for (const sc of [].concat(r.headers['set-cookie'] || [])) {
      const c = parseSetCookie(sc, httpUrl);
      if (c) storeCookie(sess, c);
    }
  });
  let upgraded = false;
  upstream.on('unexpected-response', (rq, r) => {
    log('WS upstream refused', target.host, r.statusCode);
    rq.destroy();
    if (!upgraded) rejectUpgrade(socket, 502, 'Bad Gateway');
  });
  upstream.on('error', (e) => {
    log('WS upstream error', target.host, e.message);
    if (!upgraded) rejectUpgrade(socket, 502, 'Bad Gateway');
  });

  upstream.on('open', () => {
    upgraded = true;
    log('WS open', target.host);
    req._upstreamProtocol = upstream.protocol;
    wss.handleUpgrade(req, socket, head, (client) => {
      client.on('message', (data, isBinary) => {
        if (upstream.readyState === WebSocket.OPEN) upstream.send(data, { binary: isBinary });
      });
      upstream.on('message', (data, isBinary) => {
        if (client.readyState === WebSocket.OPEN) client.send(data, { binary: isBinary });
      });
      client.on('close', (code, reason) => { log('WS client closed', code); closeSafe(upstream, code, reason); });
      upstream.on('close', (code, reason) => { log('WS upstream closed', target.host, code); closeSafe(client, code, reason); });
      client.on('error', () => upstream.terminate());
      upstream.on('error', () => client.terminate());
    });
  });
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Nimbus is running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    if (HOST === '0.0.0.0' && !PASSWORD) console.log('Warning: open to the network with no PASSWORD set.');
  });
}

module.exports = { SITE_PATCHES };
