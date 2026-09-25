/**
 * دیدبان هوشمند بازار — ورکر شماره ۴: درگاه امنیتی، هویت و مدیریت نشست‌ها
 * Module: Worker 4 — Security & Identity Gateway v2.4.0 (Hardened Enterprise Baseline)
 *
 * Core Security Architecture & Hardening Standards:
 *  1. Server-Side Authority: Browser is UNTRUSTED. Identity & RBAC strictly enforced on Cloudflare Edge.
 *  2. Additive-First D1: Interacts cleanly with `users`, `user_sessions`, `membership_requests`, `support_tickets`, `audit_logs`.
 *  3. Zero Hardcoded Credentials/Backdoors: Default passwords eliminated. Auto-generated high-entropy credentials with NIST SP 800-63B policy.
 *  4. Strict Role Hierarchy & Anti-Escalation: Role creation matrix prevents privilege escalation (ADMIN cannot grant ADMIN/SUPER_ADMIN).
 *  5. Sovereign Rank Protection: ADMIN cannot suspend or revoke equal or higher roles (SUPER_ADMIN immune to takeover).
 *  6. Precision CORS & Staging Isolation: Project-scoped origin enforcement (no wildcard *.pages.dev or *.workers.dev exploits).
 *  7. Cookie-Only Credential Transport: Session tokens emitted strictly via HttpOnly; Secure; SameSite=Lax cookies with __Host- prefix.
 *  8. Timing Attack Immunity: Constant-time PBKDF2 dummy evaluation prevents user enumeration.
 *  9. Atomic Bootstrap & Race Protection: Atomic SQL prevents concurrent Super Admin creation.
 * 10. Multi-Namespace Rate Limiting & DoS Protection: Memory-bounded sliding window per action + Content-Length <= 64KB check.
 * 11. Session Fixation Defense: Automatic revocation of all concurrent sessions upon password rotation.
 * 12. Information Disclosure Prevention: Zero raw DB/system error leaks (CWE-209 compliant).
 * 13. Append-Only Immutable Audit Logging: Zero UPDATE/DELETE on audit_logs with payload size caps.
 */

'use strict';

// ============================================================
// ۱) ثوابت و پیکربندی درگاه امنیتی سخت‌سازی‌شده (Hardened Config)
// ============================================================
const DEFAULT_CONFIG = {
  PBKDF2_ITERATIONS: 100000,
  SALT_BYTES: 16,
  SESSION_TOKEN_BYTES: 32, // 256 bits entropy
  SESSION_MAX_AGE_SECONDS: 1209600, // 14 Days (Sliding)
  SESSION_ABSOLUTE_MAX_AGE_SECONDS: 2592000, // 30 Days (Absolute Maximum Lifetime)
  LOCKOUT_THRESHOLD: 5,
  LOCKOUT_DURATION_SECONDS: 900, // 15 Minutes
  MAX_REQUEST_BODY_BYTES: 64 * 1024, // 64 KB DoS Payload Limit
  COOKIE_NAME: '__Host-td_session',
  COOKIE_FALLBACK_NAME: 'td_session',
  ALLOWED_ORIGINS: [
    'https://dbai1.pages.dev',
    'https://app.traderdiaries.com',
    'https://traderdiaries.com'
  ]
};

// ماتریس مجاز ساخت نقش بر اساس سطح دسترسی کاربر مجری (Role Creation Matrix)
const ALLOWED_ROLES_BY_ACTOR = {
  SUPER_ADMIN: ['USER', 'ASSISTANT', 'ADMIN', 'SUPER_ADMIN'],
  ADMIN: ['USER', 'ASSISTANT'],
  ASSISTANT: [],
  USER: []
};

// سلسله‌مراتب رتبه‌بندی نقش‌ها جهت کنترل دسترسی (Role Hierarchy Ranking)
const ROLE_RANK = {
  USER: 1,
  ASSISTANT: 2,
  ADMIN: 3,
  SUPER_ADMIN: 4
};

// هدرهای امنیتی پایه HTTP برای تمام پاسخ‌های JSON (HTTP Security Headers)
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
};

// ============================================================
// ماتریس رسمی سطوح دسترسی نقاط انتهایی (Endpoint Authorization Matrix)
// ============================================================
const ENDPOINT_AUTH_MATRIX = {
  PUBLIC: [
    { method: 'GET', path: '/api/health', description: 'بررسی وضعیت سلامت درگاه' },
    { method: 'POST', path: '/api/auth/register-request', description: 'ثبت درخواست عضویت عمومی' },
    { method: 'POST', path: '/api/auth/login', description: 'ورود به سامانه' },
    { method: 'GET', path: '/api/market/public', description: 'داده‌های عمومی بازار' },
    { method: 'POST', path: '/api/support/ticket', description: 'ثبت و پیگیری تیکت‌های پشتیبانی کاربر' }
  ],
  AUTHENTICATED: [
    { method: 'GET', path: '/api/auth/me', description: 'استعلام اطلاعات حساب و نشست فعال' },
    { method: 'POST', path: '/api/auth/logout', description: 'خروج از حساب کاربری و ابطال نشست' },
    { method: 'POST', path: '/api/auth/change-password', description: 'تغییر کلمه عبور حساب کاربری در پایگاه داده D1' }
  ],
  AUTHORIZED_ENTITLED: [
    { method: 'GET', path: '/api/reports/daily', requiredRoles: ['USER', 'ASSISTANT', 'ADMIN', 'SUPER_ADMIN'], requiredEntitlement: 'REPORTS_PRO', description: 'گزارش‌های تحلیلی روزانه و تاریخی' },
    { method: 'POST', path: '/api/ai/forecast', requiredRoles: ['USER', 'ADMIN', 'SUPER_ADMIN'], requiredEntitlement: 'INTELLIGENCE_PRO', description: 'استنتاج پیش‌بینی هوش مصنوعی' }
  ],
  ADMIN_ONLY: [
    { method: 'GET', path: '/api/admin/requests', requiredRoles: ['ADMIN', 'SUPER_ADMIN', 'ASSISTANT'], description: 'مشاهده کارتابل درخواست‌های عضویت' },
    { method: 'POST', path: '/api/admin/users/approve', requiredRoles: ['ADMIN', 'SUPER_ADMIN'], description: 'تایید عضویت و ایجاد کاربر' },
    { method: 'POST', path: '/api/admin/users/suspend', requiredRoles: ['ADMIN', 'SUPER_ADMIN'], description: 'تعلیق کاربر و ابطال آنی نشست‌ها' },
    { method: 'GET', path: '/api/admin/users', requiredRoles: ['ADMIN', 'SUPER_ADMIN'], description: 'مشاهده لیست کاربران سامانه' },
    { method: 'GET', path: '/api/admin/tickets', requiredRoles: ['ADMIN', 'SUPER_ADMIN'], description: 'مشاهده کارتابل تیکت‌های پشتیبانی' },
    { method: 'POST', path: '/api/admin/tickets/reply', requiredRoles: ['ADMIN', 'SUPER_ADMIN'], description: 'پاسخ به تیکت‌های پشتیبانی' },
    { method: 'GET', path: '/api/admin/audit-logs', requiredRoles: ['ADMIN', 'SUPER_ADMIN'], description: 'مشاهده رویدادهای ممیزی امنیتی' }
  ],
  SUPER_ADMIN_ONLY: [
    { method: 'POST', path: '/api/admin/users/role', requiredRoles: ['SUPER_ADMIN'], description: 'ارتقا و تغییر نقش کاربران توسط سوپرادمین' },
    { method: 'POST', path: '/api/admin/broadcast', requiredRoles: ['SUPER_ADMIN'], description: 'ارسال اعلان و پیام سراسری سیستم' },
    { method: 'POST', path: '/api/admin/break-glass/recover-admin', requiresSecret: true, description: 'بازیابی اضطراری سوپرادمین با سکرت موقت' },
    { method: 'POST', path: '/api/auth/emergency-break-glass', requiresSecret: true, description: 'بازیابی اضطراری سوپرادمین با سکرت موقت (مسیر هم‌ارز)' }
  ],
  INTERNAL_ONLY: [
    { method: 'ANY', path: '/api/internal/*', requiresSignedContext: true, description: 'ارتباطات بین‌ورکری امضاشده' }
  ]
};

// حافظه موقت لبه برای ریت‌لیمیت IP با مکانیزم پاکسازی حافظه (Bounded In-Memory IP Limiter)
const ipRateLimitMap = new Map();
const MAX_RATE_LIMIT_MAP_ENTRIES = 5000;

// حافظه موقت بررسی عدم تکرار Nonce بین‌ورکری (Replay Cache with TTL)
const nonceCache = new Map();

// ============================================================
// ۲) ابزارها و ماژول‌های رمزنگاری لبه (Web Crypto API Suite)
// ============================================================
const CryptoUtils = {
  /**
   * مقایسه امن در زمان ثابت با پیش‌هش SHA-256 (Constant-Time Comparison with Zero Length Leak)
   */
  async timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') {
      return false;
    }
    // پیش‌هش هر دو رشته با SHA-256 تا طول هر دو ورودی دقیقاً ۳۲ بایت یکنواخت شود
    const hashA = await this.sha256Bytes(a);
    const hashB = await this.sha256Bytes(b);
    
    let result = 0;
    for (let i = 0; i < 32; i++) {
      result |= hashA[i] ^ hashB[i];
    }
    return result === 0 && a === b;
  },

  /**
   * تولید بایت‌های تصادفی امن
   */
  getRandomBytes(length = 16) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  },

  /**
   * تبدیل Uint8Array به رشته هگزادسیمال
   */
  bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /**
   * تبدیل رشته هگزادسیمال به Uint8Array
   */
  hexToBytes(hex) {
    const clean = hex.trim();
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
    }
    return bytes;
  },

  /**
   * تبدیل Uint8Array به رشته Base64URL بدون پدینگ
   */
  bytesToBase64Url(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const b64 = btoa(binary);
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },

  /**
   * محاسبه بایت‌های هش SHA-256
   */
  async sha256Bytes(strOrBytes) {
    const data = typeof strOrBytes === 'string' ? new TextEncoder().encode(strOrBytes) : strOrBytes;
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
  },

  /**
   * محاسبه هش SHA-256 رشته یا بافر به صورت هگزادسیمال
   */
  async sha256Hex(strOrBytes) {
    const bytes = await this.sha256Bytes(strOrBytes);
    return this.bytesToHex(bytes);
  },

  /**
   * مشتق‌سازی کلید هش با الگوریتم PBKDF2-HMAC-SHA256
   */
  async derivePbkdf2Hash(password, saltHex, iterations = 100000) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const saltBytes = this.hexToBytes(saltHex);
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256 // 32 bytes (256 bits)
    );

    return this.bytesToHex(new Uint8Array(derivedBits));
  },

  /**
   * اعتبارسنجی رمزعبور با PBKDF2 با حفاظت زمان‌ثابت
   */
  async verifyPbkdf2Password(password, saltHex, expectedHashHex, iterations = 100000) {
    if (!password || !saltHex || !expectedHashHex) return false;
    const computedHashHex = await this.derivePbkdf2Hash(password, saltHex, iterations);
    return this.timingSafeEqual(computedHashHex, expectedHashHex);
  },

  /**
   * تولید کلمه عبور تصادفی با آنتروپی بالا و تنوع نویسه‌ها (NIST SP 800-63B)
   */
  generateSecurePassword(length = 16) {
    const uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lowercase = 'abcdefghijkmnopqrstuvwxyz';
    const numbers = '23456789';
    const symbols = '!@#$%^&*()_+~|}{[]:;?><,.-=';
    const allChars = uppercase + lowercase + numbers + symbols;

    const randomBytes = this.getRandomBytes(length + 4);
    let pwd = [
      uppercase[randomBytes[0] % uppercase.length],
      lowercase[randomBytes[1] % lowercase.length],
      numbers[randomBytes[2] % numbers.length],
      symbols[randomBytes[3] % symbols.length]
    ];

    for (let i = 4; i < length; i++) {
      pwd.push(allChars[randomBytes[i] % allChars.length]);
    }

    // شافل تصادفی کاراکترها
    for (let i = pwd.length - 1; i > 0; i--) {
      const j = randomBytes[i] % (i + 1);
      const temp = pwd[i];
      pwd[i] = pwd[j];
      pwd[j] = temp;
    }

    return pwd.join('');
  },

  /**
   * اعتبارسنجی پیچیدگی و طول کلمه عبور مطابق با استاندارد NIST SP 800-63B
   */
  validatePasswordStrength(password) {
    if (!password || typeof password !== 'string') return { valid: false, reason: 'رمز عبور نمی‌تواند خالی باشد.' };
    if (password.length < 12) {
      return { valid: false, reason: 'کلمه عبور باید حداقل ۱۲ کاراکتر باشد.' };
    }
    let classCount = 0;
    if (/[A-Z]/.test(password)) classCount++;
    if (/[a-z]/.test(password)) classCount++;
    if (/[0-9]/.test(password)) classCount++;
    if (/[^A-Za-z0-9]/.test(password)) classCount++;

    if (classCount < 3) {
      return { valid: false, reason: 'کلمه عبور باید ترکیبی از حداقل ۳ دسته (حروف بزرگ، حروف کوچک، اعداد و نمادها) باشد.' };
    }

    return { valid: true };
  },

  /**
   * اعتبارسنجی ساختار نام کاربری
   */
  validateUsername(username) {
    if (!username || typeof username !== 'string') return false;
    return /^[a-zA-Z0-9_]{3,32}$/.test(username.trim());
  },

  /**
   * اعتبارسنجی اطلاعات تماس (ایمیل معتبر یا شماره تلفن استاندارد)
   */
  validateContactInfo(contactInfo) {
    if (!contactInfo || typeof contactInfo !== 'string') return false;
    const clean = contactInfo.trim();
    const emailRegex = /^[\w.+-]+@[\w-]+\.[\w.-]+$/;
    const phoneRegex = /^\+?\d{7,15}$/;
    return emailRegex.test(clean) || phoneRegex.test(clean);
  },

  /**
   * امضای پیام با الگوریتم HMAC-SHA256
   */
  async signHmacSha256(message, secret) {
    if (!secret) {
      throw new Error('HMAC secret is mandatory and cannot be empty.');
    }
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      enc.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
    return this.bytesToBase64Url(new Uint8Array(sig));
  },

  /**
   * اعتبارسنجی امضای HMAC-SHA256 با مقایسه زمان‌ثابت
   */
  async verifyHmacSha256(message, signatureBase64Url, secret) {
    if (!secret || !signatureBase64Url) return false;
    try {
      const expectedSig = await this.signHmacSha256(message, secret);
      return this.timingSafeEqual(expectedSig, signatureBase64Url);
    } catch (e) {
      return false;
    }
  }
};

// ============================================================
// ۳) مدیریت پروتکل ارتباط بین‌ورکری (Service-to-Service Trust)
// ============================================================
const ServiceTrust = {
  /**
   * تولید هدر کانتکست امضاشده برای ارسال به ورکر ۲ یا ورکر ۳
   */
  async createSignedContext(user, session, targetAudience, method, path, secret) {
    if (!secret) {
      throw new Error('INTER_WORKER_SECRET is not configured on Worker 4.');
    }
    const now = Math.floor(Date.now() / 1000);
    const nonce = CryptoUtils.bytesToHex(CryptoUtils.getRandomBytes(12));
    const payload = {
      iss: 'worker4.gateway',
      aud: targetAudience, // 'worker2.reporter' | 'worker3.ai'
      sub: user.id,
      username: user.username,
      sid: session.id,
      role: user.role,
      status: user.status,
      method: method.toUpperCase(),
      path: path.split('?')[0],
      nonce,
      ts: now,
      exp: now + 30 // ۳۰ ثانیه اعتبار فشرده
    };

    const jsonStr = JSON.stringify(payload);
    const contextBase64 = CryptoUtils.bytesToBase64Url(new TextEncoder().encode(jsonStr));
    const signature = await CryptoUtils.signHmacSha256(contextBase64, secret);

    return {
      'X-Internal-Gateway-Context': contextBase64,
      'X-Internal-Gateway-Signature': signature
    };
  },

  /**
   * اعتبارسنجی هدرهای دریافتی از درگاه در ورکر مقصد با حفاظت Replay و انطباق ۳۰ ثانیه‌ای
   */
  async verifySignedContext(contextBase64, signature, expectedAudience, method, path, secret) {
    if (!contextBase64 || !signature || !secret) return { valid: false, reason: 'MISSING_HEADERS' };

    const isSigValid = await CryptoUtils.verifyHmacSha256(contextBase64, signature, secret);
    if (!isSigValid) return { valid: false, reason: 'INVALID_SIGNATURE' };

    try {
      const decodedStr = atob(contextBase64.replace(/-/g, '+').replace(/_/g, '/'));
      const payload = JSON.parse(decodedStr);
      const now = Math.floor(Date.now() / 1000);

      // اعتبارسنجی پنجره زمانی ۳۰ ثانیه‌ای
      if (Math.abs(now - payload.ts) > 30 || payload.exp < now) {
        return { valid: false, reason: 'EXPIRED_TOKEN' };
      }
      if (payload.aud !== expectedAudience) return { valid: false, reason: 'AUDIENCE_MISMATCH' };
      if (payload.method !== method.toUpperCase()) return { valid: false, reason: 'METHOD_MISMATCH' };
      if (payload.path !== path.split('?')[0]) return { valid: false, reason: 'PATH_MISMATCH' };

      // گارد ضد حمله تکرار (Replay Attack Guard via Nonce)
      if (nonceCache.has(payload.nonce)) return { valid: false, reason: 'REPLAY_DETECTED' };
      nonceCache.set(payload.nonce, payload.exp);

      // پاکسازی خودکار نانس‌های منقضی
      for (const [n, exp] of nonceCache.entries()) {
        if (exp < now) nonceCache.delete(n);
      }

      return { valid: true, payload };
    } catch (e) {
      return { valid: false, reason: 'MALFORMED_CONTEXT' };
    }
  }
};

// ============================================================
// ۴) ماژول ممیزی امنیتی غیرقابل تغییر (Append-Only Audit Logger)
// ============================================================
const AuditLogger = {
  /**
   * ثبت قطعی رویداد ممیزی (منحصراً INSERT، با کنترل سقف حجم متادیتا و بدون UPDATE یا DELETE)
   */
  async record(db, params = {}) {
    if (!db || typeof db.prepare !== 'function') return false;
    const {
      actor_id = null,
      actor_role = 'ANONYMOUS',
      action,
      target_type = 'SYSTEM',
      target_id = null,
      ip_hash = null,
      metadata = {},
      details = null
    } = params;

    const createdAt = new Date().toISOString();
    const combinedData = details ? { ...metadata, ...details } : metadata;
    let metadataJson = JSON.stringify(combinedData);

    // سقف کاراکتر برای متادیتای لاگ ممیزی جهت جلوگیری از پر شدن حافظه پایگاه‌داده (L-4)
    if (metadataJson.length > 2000) {
      metadataJson = metadataJson.substring(0, 1990) + '..."}';
    }

    try {
      await db.prepare(`
        INSERT INTO audit_logs (actor_id, actor_role, action, target_type, target_id, ip_hash, metadata_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        actor_id,
        actor_role,
        action,
        target_type,
        target_id ? String(target_id) : null,
        ip_hash,
        metadataJson,
        createdAt
      ).run();
      return true;
    } catch (e) {
      console.error('[AuditLogger Error]:', e);
      return false;
    }
  }
};

// ============================================================
// ۵) ابزارهای کوکی، هدر و CORS دقیق (Precision CORS & Cookies)
// ============================================================
const HttpUtils = {
  /**
   * اعتبارسنجی سخت‌گیرانه مبدا (Strict Origin Validator — C-4 Fix)
   * جلوگیری قطعی از وایلدکارد باز روی دامنه‌های اشتراکی *.pages.dev و *.workers.dev
   */
  isOriginAllowed(origin, env) {
    if (!origin) return true;
    const allowed = (env && env.ALLOWED_ORIGINS)
      ? env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
      : DEFAULT_CONFIG.ALLOWED_ORIGINS;

    // تطابق دقیق با دامنه‌های مشخص پروژه
    if (allowed.includes(origin)) return true;

    // در محیط توسعه/Staging فقط زیردامنه‌های رسمی پروژه dbai1 مجاز هستند (نه کل pages.dev!)
    const isDevOrPreview = env && env.ENVIRONMENT !== 'production';
    if (isDevOrPreview && /^https:\/\/[a-z0-9-]+\.dbai1\.pages\.dev$/.test(origin)) {
      return true;
    }

    // دامنه‌های رسمی پروژه دیدبان / TraderDiaries
    if (/^https:\/\/([a-z0-9-]+\.)?traderdiaries\.com$/.test(origin)) return true;

    // محیط توسعه محلی با هر پورتی
    if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;

    return false;
  },

  /**
   * ساخت هدرهای CORS و هدرهای امنیتی پایه (C-5 & M-4 Fix)
   * عدم بازتاب Origin غیرمجاز و تزریق دائمی هدرهای محافظتی
   */
  buildCorsHeaders(request, env) {
    const origin = request.headers.get('Origin') || '';
    const isAllowed = this.isOriginAllowed(origin, env);

    const headers = {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token, X-Break-Glass-Secret',
      ...SECURITY_HEADERS
    };

    if (origin && isAllowed) {
      headers['Access-Control-Allow-Origin'] = origin;
      headers['Access-Control-Allow-Credentials'] = 'true';
      headers['Vary'] = 'Origin';
    } else if (!origin) {
      // درخواست‌های داخلی سرور به سرور یا کلاینت‌های مستقیم
      headers['Vary'] = 'Origin';
    }

    return headers;
  },

  /**
   * استخراج کوکی‌ها از هدر Cookie
   */
  parseCookies(request) {
    const cookieHeader = request.headers.get('Cookie') || '';
    const cookies = {};
    cookieHeader.split(';').forEach(pair => {
      const [name, ...rest] = pair.trim().split('=');
      if (name && rest.length > 0) {
        cookies[name.trim()] = decodeURIComponent(rest.join('='));
      }
    });
    return cookies;
  },

  /**
   * ساخت هدر Set-Cookie برای سشن کاربر (L-1 Fix: پاکسازی ترنری)
   */
  buildSessionCookie(token, maxAgeSeconds = 1209600, isProductionUnified = false) {
    const name = isProductionUnified ? DEFAULT_CONFIG.COOKIE_NAME : DEFAULT_CONFIG.COOKIE_FALLBACK_NAME;
    return `${name}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
  },

  /**
   * ساخت هدر Set-Cookie برای حذف سشن در خروج (Logout)
   */
  buildDeleteCookie(isProductionUnified = false) {
    const name = isProductionUnified ? DEFAULT_CONFIG.COOKIE_NAME : DEFAULT_CONFIG.COOKIE_FALLBACK_NAME;
    return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
  },

  /**
   * ارزیابی چندلایه حفاظت CSRF
   */
  validateCsrf(request, env) {
    const method = request.method.toUpperCase();
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return true;

    const origin = request.headers.get('Origin');
    const referer = request.headers.get('Referer');

    if (origin) {
      if (!this.isOriginAllowed(origin, env)) return false;
    } else if (referer) {
      try {
        const refOrigin = new URL(referer).origin;
        if (!this.isOriginAllowed(refOrigin, env)) return false;
      } catch (e) {
        return false;
      }
    }

    return true;
  },

  /**
   * بررسی ریت‌لیمیت IP با تفکیک اکشن‌ها و مدیریت حافظه ایزولیت (M-3, M-5, L-3 Fix)
   */
  checkIpRateLimit(clientIp, maxPerMin = 15, actionNamespace = 'default') {
    if (!clientIp) return true;
    const now = Date.now();
    const windowStart = now - 60000;
    const key = `${actionNamespace}:${clientIp}`;

    // پاکسازی دوره‌ای حافظه موقت در صورت رشد بیش از حد (LRU/TTL Safety)
    if (ipRateLimitMap.size > MAX_RATE_LIMIT_MAP_ENTRIES) {
      for (const [k, timestamps] of ipRateLimitMap.entries()) {
        const valid = timestamps.filter(t => t > windowStart);
        if (valid.length === 0) {
          ipRateLimitMap.delete(k);
        } else {
          ipRateLimitMap.set(k, valid);
        }
      }
    }

    const record = ipRateLimitMap.get(key) || [];
    const recent = record.filter(t => t > windowStart);
    if (recent.length >= maxPerMin) return false;
    recent.push(now);
    ipRateLimitMap.set(key, recent);
    return true;
  }
};

// ============================================================
// ۶) موتور اصلی ورکر شماره ۴ (Worker 4 Request Handler)
// ============================================================
const Worker4Handler = {
  async handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    const corsHeaders = HttpUtils.buildCorsHeaders(request, env);
    const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '127.0.0.1';
    const ipHash = await CryptoUtils.sha256Hex(clientIp);
    const userAgent = request.headers.get('User-Agent') || 'Unknown';
    const isProduction = url.hostname === 'app.traderdiaries.com' || url.hostname.endsWith('.traderdiaries.com');

    // مدیریت درخواست‌های مقدماتی OPTIONS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // کنترل حجم بدنه درخواست جهت مهار حملات DoS (M-8 Fix)
    if (['POST', 'PUT', 'PATCH'].includes(request.method.toUpperCase())) {
      const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
      if (contentLength > DEFAULT_CONFIG.MAX_REQUEST_BODY_BYTES) {
        return new Response(JSON.stringify({ error: 'PAYLOAD_TOO_LARGE', message: 'حجم درخواست بیش از حد مجاز است (حداکثر ۶۴ کیلوبایت).' }), {
          status: 413,
          headers: corsHeaders
        });
      }
    }

    // اعتبارسنجی لایه حفاظتی ضد CSRF برای متدهای تغییردهنده داده
    if (!HttpUtils.validateCsrf(request, env)) {
      return new Response(JSON.stringify({ error: 'CSRF_REJECTED', message: 'درخواست به دلیل عدم تطابق مبدا امنیتی رد شد.' }), {
        status: 403,
        headers: corsHeaders
      });
    }

    const db = env && env.DB;
    if (!db) {
      return new Response(JSON.stringify({ error: 'DATABASE_UNAVAILABLE', message: 'اتصال پایگاه داده ابری D1 برقرار نیست.' }), {
        status: 503,
        headers: corsHeaders
      });
    }

    // ========================================================================
    // GET /api/health — بررسی وضعیت سلامت درگاه امنیتی
    // ========================================================================
    if (url.pathname === '/api/health') {
      return new Response(JSON.stringify({
        status: 'OK',
        module: 'worker4-auth-gateway',
        version: '2.4.0',
        timestamp: new Date().toISOString(),
        kdf: 'PBKDF2-HMAC-SHA256',
        isolation: 'FAULT_ISOLATED',
        security_baseline: 'HARDENED_ENTERPRISE'
      }), { status: 200, headers: corsHeaders });
    }

    // ========================================================================
    // POST /api/auth/register-request — ثبت درخواست عضویت متقاضی جدید
    // ========================================================================
    if (url.pathname === '/api/auth/register-request' && request.method === 'POST') {
      if (!HttpUtils.checkIpRateLimit(clientIp, 5, 'register_req')) {
        return new Response(JSON.stringify({ error: 'RATE_LIMITED', message: 'تعداد درخواست‌های ارسالی بیش از حد مجاز است. لطفاً کمی بعد تلاش کنید.' }), {
          status: 429,
          headers: corsHeaders
        });
      }

      try {
        const body = await request.json();
        const fullName = (body.full_name || body.fullName || '').trim();
        const contactInfo = (body.contact_info || body.contactInfo || '').trim();
        const intendedUse = (body.intended_use || body.intendedUse || '').trim();

        if (!fullName || fullName.length < 3 || fullName.length > 80) {
          return new Response(JSON.stringify({ error: 'INVALID_NAME', message: 'نام و نام خانوادگی باید بین ۳ تا ۸۰ کاراکتر باشد.' }), {
            status: 400,
            headers: corsHeaders
          });
        }
        if (!contactInfo || !CryptoUtils.validateContactInfo(contactInfo)) {
          return new Response(JSON.stringify({ error: 'INVALID_CONTACT', message: 'شماره تماس یا ایمیل معتبر وارد کنید.' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        const createdAt = new Date().toISOString();
        const insertRes = await db.prepare(`
          INSERT INTO membership_requests (full_name, contact_info, intended_use, status, created_at)
          VALUES (?, ?, ?, 'PENDING', ?)
        `).bind(fullName, contactInfo, intendedUse, createdAt).run();

        const requestId = insertRes.meta ? insertRes.meta.last_row_id : null;

        await AuditLogger.record(db, {
          actor_role: 'APPLICANT',
          action: 'MEMBERSHIP_REQUEST_CREATED',
          target_type: 'MEMBERSHIP_REQUEST',
          target_id: requestId,
          ip_hash: ipHash,
          metadata: { fullName, contactInfo }
        });

        return new Response(JSON.stringify({
          success: true,
          status: 'PENDING',
          requestId,
          message: 'درخواست عضویت شما با موفقیت ثبت شد و پس از بررسی توسط مدیر سامانه فعال خواهد شد.'
        }), { status: 201, headers: corsHeaders });
      } catch (e) {
        console.error('[RegisterRequest Error]:', e);
        return new Response(JSON.stringify({ error: 'SERVER_ERROR', message: 'خطای سرور در ثبت درخواست عضویت.' }), {
          status: 500,
          headers: corsHeaders
        });
      }
    }

    // ========================================================================
    // POST /api/support/ticket — ثبت تیکت پشتیبانی و پیام‌های کاربر (C-6 & M-3 Fix)
    // ========================================================================
    if (url.pathname === '/api/support/ticket' && request.method === 'POST') {
      if (!HttpUtils.checkIpRateLimit(clientIp, 5, 'support_ticket')) {
        return new Response(JSON.stringify({ error: 'RATE_LIMITED', message: 'تعداد ارسال تیکت بیش از حد مجاز است. لطفاً کمی بعد تلاش کنید.' }), {
          status: 429,
          headers: corsHeaders
        });
      }

      try {
        const body = await request.json();
        const name = (body.name || '').trim();
        const contact = (body.contact || '').trim();
        const category = (body.category || 'GENERAL').trim();
        const subject = (body.subject || '').trim();
        const message = (body.message || '').trim();

        if (!subject || !message || subject.length < 3 || message.length < 5) {
          return new Response(JSON.stringify({ error: 'INVALID_INPUT', message: 'موضوع و متن پیام تیکت الزامی هستند.' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        const ticketId = 'TD-' + Date.now().toString(36).toUpperCase() + '-' + CryptoUtils.bytesToHex(CryptoUtils.getRandomBytes(2)).toUpperCase();
        const createdAt = new Date().toISOString();

        // ذخیره ساختاریافته در جدول support_tickets
        try {
          await db.prepare(`
            INSERT INTO support_tickets (ticket_id, name, contact_info, category, subject, message, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?)
          `).bind(ticketId, name, contact, category, subject, message, createdAt).run();
        } catch (tblErr) {
          console.error('[SupportTicket DB Insert Error]:', tblErr);
        }

        await AuditLogger.record(db, {
          actor_role: 'USER',
          action: 'SUPPORT_TICKET_CREATED',
          target_type: 'SUPPORT_TICKET',
          target_id: ticketId,
          ip_hash: ipHash,
          details: { name, contact, category, subject }
        });

        return new Response(JSON.stringify({
          success: true,
          ticketId,
          message: `تیکت پشتیبانی شما با شماره پیگیری ${ticketId} با موفقیت ثبت گردید و بررسی خواهد شد.`
        }), {
          status: 201,
          headers: corsHeaders
        });

      } catch (err) {
        console.error('[SupportTicket Error]:', err);
        return new Response(JSON.stringify({ error: 'INTERNAL_ERROR', message: 'خطا در ثبت تیکت. لطفاً بعداً تلاش کنید.' }), {
          status: 500,
          headers: corsHeaders
        });
      }
    }

    // ========================================================================
    // POST /api/auth/login — ورود با مصونیت در برابر تحلیل زمانی و Race Condition (M-1 & M-2 Fix)
    // ========================================================================
    if (url.pathname === '/api/auth/login' && request.method === 'POST') {
      if (!HttpUtils.checkIpRateLimit(clientIp, 10, 'login')) {
        return new Response(JSON.stringify({ error: 'RATE_LIMITED', message: 'تعداد دفعات ورود بیش از حد مجاز است. لطفاً یک دقیقه بعد تلاش کنید.' }), {
          status: 429,
          headers: corsHeaders
        });
      }

      try {
        const body = await request.json();
        const username = (body.username || '').trim().toLowerCase();
        const password = String(body.password || '');

        if (!username || !password) {
          return new Response(JSON.stringify({ error: 'INVALID_INPUT', message: 'نام کاربری و کلمه عبور الزامی هستند.' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // ۱. بررسی اتمیک راه‌اندازی اولین کاربر (First-User Super Admin Bootstrap Guard with Race-Condition Immunity — M-1 Fix)
        const anyUser = await db.prepare('SELECT id FROM users LIMIT 1').first();

        if (!anyUser) {
          const saltHex = CryptoUtils.bytesToHex(CryptoUtils.getRandomBytes(DEFAULT_CONFIG.SALT_BYTES));
          const iterations = env.PBKDF2_ITERATIONS ? parseInt(env.PBKDF2_ITERATIONS, 10) : DEFAULT_CONFIG.PBKDF2_ITERATIONS;
          const passwordHash = await CryptoUtils.derivePbkdf2Hash(password, saltHex, iterations);
          const createdAt = new Date().toISOString();
          const fullName = username === 'admin' ? 'مدیر ارشد دیدبان' : (username.charAt(0).toUpperCase() + username.slice(1));

          // درج اتمیک شرطی جهت جلوگیری از Race Condition بین چند درخواست همزمان
          const bootstrapRes = await db.prepare(`
            INSERT INTO users (username, password_hash, salt, iterations, full_name, role, status, created_at, approved_at)
            SELECT ?, ?, ?, ?, ?, 'SUPER_ADMIN', 'ACTIVE', ?, ?
            WHERE NOT EXISTS (SELECT 1 FROM users)
          `).bind(username, passwordHash, saltHex, iterations, fullName, createdAt, createdAt).run().catch(e => null);

          // اگر درج اتمیک با موفقیت انجام شد، سشن سوپرادمین صادر می‌شود
          if (bootstrapRes && bootstrapRes.meta && (bootstrapRes.meta.changes > 0 || bootstrapRes.meta.last_row_id)) {
            const newUserId = bootstrapRes.meta.last_row_id || 1;
            const sessionToken = CryptoUtils.bytesToBase64Url(CryptoUtils.getRandomBytes(DEFAULT_CONFIG.SESSION_TOKEN_BYTES));
            const sessionTokenHash = await CryptoUtils.sha256Hex(sessionToken);
            const expiresAt = new Date(Date.now() + DEFAULT_CONFIG.SESSION_MAX_AGE_SECONDS * 1000).toISOString();

            await db.prepare(`
              INSERT INTO user_sessions (session_token_hash, user_id, ip_hash, user_agent, created_at, expires_at, last_active_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(sessionTokenHash, newUserId, ipHash, userAgent, createdAt, expiresAt, createdAt).run();

            const cookieHeader = HttpUtils.buildSessionCookie(sessionToken, DEFAULT_CONFIG.SESSION_MAX_AGE_SECONDS, isProduction);
            const respHeaders = new Headers(corsHeaders);
            respHeaders.append('Set-Cookie', cookieHeader);

            await AuditLogger.record(db, {
              actor_id: newUserId,
              actor_role: 'SUPER_ADMIN',
              action: 'INITIAL_SUPER_ADMIN_BOOTSTRAP',
              target_type: 'USER',
              target_id: String(newUserId),
              ip_hash: ipHash,
              metadata: { username, role: 'SUPER_ADMIN' }
            });

            return new Response(JSON.stringify({
              success: true,
              message: 'حساب کاربری سوپرادمین با موفقیت راه‌اندازی و ورود انجام شد.',
              user: {
                id: newUserId,
                username,
                fullName,
                role: 'SUPER_ADMIN',
                status: 'ACTIVE'
              }
            }), { status: 200, headers: respHeaders });
          }
        }

        // استعلام اطلاعات کاربر از پایگاه داده D1
        const user = await db.prepare(`
          SELECT * FROM users WHERE username = ?
        `).bind(username).first();

        const genericAuthError = { error: 'AUTH_FAILED', message: 'نام کاربری یا کلمه عبور نادرست است.' };

        // ۲. مقابله کامل با حمله تحلیل زمانی و کشف نام کاربری (Constant-Time Dummy Execution — M-2 Fix)
        if (!user) {
          const iterations = env.PBKDF2_ITERATIONS ? parseInt(env.PBKDF2_ITERATIONS, 10) : DEFAULT_CONFIG.PBKDF2_ITERATIONS;
          // اجرای عمدی مشتق‌سازی هش ساختگی برای یکسان‌سازی زمان پاسخ‌دهی با کاربر واقعی
          await CryptoUtils.derivePbkdf2Hash(password, '0123456789abcdef0123456789abcdef', iterations);

          await AuditLogger.record(db, {
            actor_role: 'ANONYMOUS',
            action: 'LOGIN_FAILED_UNKNOWN_USER',
            target_type: 'USER',
            target_id: username,
            ip_hash: ipHash
          });
          return new Response(JSON.stringify(genericAuthError), { status: 401, headers: corsHeaders });
        }

        // بررسی وضعیت تعلیق یا انتظار کاربر
        if (user.status === 'SUSPENDED') {
          await AuditLogger.record(db, {
            actor_id: user.id,
            actor_role: user.role,
            action: 'LOGIN_BLOCKED_SUSPENDED',
            target_type: 'USER',
            target_id: user.id,
            ip_hash: ipHash
          });
          return new Response(JSON.stringify({ error: 'ACCOUNT_SUSPENDED', message: 'حساب کاربری شما مسدود شده است. با پشتیبانی تماس بگیرید.' }), {
            status: 403,
            headers: corsHeaders
          });
        }

        if (user.status === 'PENDING') {
          return new Response(JSON.stringify({ error: 'ACCOUNT_PENDING', message: 'حساب کاربری شما هنوز توسط مدیر سامانه تایید نشده است.' }), {
            status: 403,
            headers: corsHeaders
          });
        }

        // بررسی قفل موقت ناشی از Brute Force
        const nowMs = Date.now();
        if (user.locked_until && new Date(user.locked_until).getTime() > nowMs) {
          const remainMins = Math.ceil((new Date(user.locked_until).getTime() - nowMs) / 60000);
          return new Response(JSON.stringify({
            error: 'ACCOUNT_LOCKED',
            message: `حساب شما به دلیل تلاش‌های ناموفق متوالی به مدت ${remainMins} دقیقه دیگر قفل موقت است.`
          }), { status: 429, headers: corsHeaders });
        }

        // اعتبارسنجی کلمه عبور با PBKDF2-HMAC-SHA256
        const iterations = user.iterations || (env.PBKDF2_ITERATIONS ? parseInt(env.PBKDF2_ITERATIONS, 10) : DEFAULT_CONFIG.PBKDF2_ITERATIONS);
        const isPasswordCorrect = await CryptoUtils.verifyPbkdf2Password(password, user.salt, user.password_hash, iterations);

        if (!isPasswordCorrect) {
          const newFailCount = (user.failed_login_count || 0) + 1;
          const lockoutThreshold = env.LOCKOUT_THRESHOLD ? parseInt(env.LOCKOUT_THRESHOLD, 10) : DEFAULT_CONFIG.LOCKOUT_THRESHOLD;
          let lockUntilIso = null;

          if (newFailCount >= lockoutThreshold) {
            const lockSecs = env.LOCKOUT_DURATION_SECONDS ? parseInt(env.LOCKOUT_DURATION_SECONDS, 10) : DEFAULT_CONFIG.LOCKOUT_DURATION_SECONDS;
            lockUntilIso = new Date(Date.now() + lockSecs * 1000).toISOString();
          }

          await db.prepare(`
            UPDATE users SET failed_login_count = ?, locked_until = ? WHERE id = ?
          `).bind(newFailCount, lockUntilIso, user.id).run();

          await AuditLogger.record(db, {
            actor_id: user.id,
            actor_role: user.role,
            action: 'LOGIN_FAILED_BAD_PASSWORD',
            target_type: 'USER',
            target_id: user.id,
            ip_hash: ipHash,
            metadata: { failCount: newFailCount, locked: !!lockUntilIso }
          });

          return new Response(JSON.stringify(genericAuthError), { status: 401, headers: corsHeaders });
        }

        // بازنشانی شمارنده خطای ورود پس از رمز موفق
        await db.prepare(`
          UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = ?, last_login_ip_hash = ? WHERE id = ?
        `).bind(new Date().toISOString(), ipHash, user.id).run();

        // تولید توکن نشست با آنتروپی بالا (۲۵۶ بیتی)
        const rawTokenBytes = CryptoUtils.getRandomBytes(DEFAULT_CONFIG.SESSION_TOKEN_BYTES);
        const rawTokenString = CryptoUtils.bytesToBase64Url(rawTokenBytes);
        const tokenHash = await CryptoUtils.sha256Hex(rawTokenString);

        const maxAge = env.SESSION_MAX_AGE_SECONDS ? parseInt(env.SESSION_MAX_AGE_SECONDS, 10) : DEFAULT_CONFIG.SESSION_MAX_AGE_SECONDS;
        const nowIso = new Date().toISOString();
        const expiresIso = new Date(Date.now() + maxAge * 1000).toISOString();

        // ذخیره هش توکن در جدول user_sessions
        const sessionRes = await db.prepare(`
          INSERT INTO user_sessions (session_token_hash, user_id, ip_hash, user_agent, created_at, expires_at, last_active_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(tokenHash, user.id, ipHash, userAgent, nowIso, expiresIso, nowIso).run();

        const sessionId = sessionRes.meta ? sessionRes.meta.last_row_id : null;

        await AuditLogger.record(db, {
          actor_id: user.id,
          actor_role: user.role,
          action: 'LOGIN_SUCCESS',
          target_type: 'SESSION',
          target_id: sessionId,
          ip_hash: ipHash
        });

        // تنظیم کوکی نشست امن (منحصراً از طریق HttpOnly Cookie، بدون بازگرداندن توکن در JSON)
        const setCookieHeader = HttpUtils.buildSessionCookie(rawTokenString, maxAge, isProduction);
        const respHeaders = new Headers(corsHeaders);
        respHeaders.append('Set-Cookie', setCookieHeader);

        return new Response(JSON.stringify({
          success: true,
          user: {
            id: user.id,
            username: user.username,
            full_name: user.full_name,
            role: user.role,
            status: user.status
          },
          expiresAt: expiresIso
        }), { status: 200, headers: respHeaders });

      } catch (e) {
        console.error('[Login Error]:', e);
        return new Response(JSON.stringify({ error: 'SERVER_ERROR', message: 'خطای سیستمی در فرآیند احراز هویت.' }), {
          status: 500,
          headers: corsHeaders
        });
      }
    }

    // ========================================================================
    // تابع کمکی: استخراج و اعتبارسنجی نشست جاری (با سقف انقضای مطلق — L-5 & L-7 Fix)
    // ========================================================================
    const extractAndValidateSession = async () => {
      const cookies = HttpUtils.parseCookies(request);
      let rawToken = cookies[DEFAULT_CONFIG.COOKIE_NAME] || cookies[DEFAULT_CONFIG.COOKIE_FALLBACK_NAME];

      // پشتیبانی از هدر Authorization: Bearer صرفاً به عنوان مکمل کلاینت‌های غیرمرورگری (L-9)
      if (!rawToken) {
        const authHeader = request.headers.get('Authorization') || '';
        if (authHeader.startsWith('Bearer ')) {
          rawToken = authHeader.slice(7).trim();
        }
      }

      if (!rawToken) return null;

      const tokenHash = await CryptoUtils.sha256Hex(rawToken);
      const sessionRow = await db.prepare(`
        SELECT s.*, u.username, u.full_name, u.role, u.status, u.locked_until
        FROM user_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token_hash = ? AND s.revoked_at IS NULL
      `).bind(tokenHash).first();

      if (!sessionRow) return null;

      const nowIso = new Date().toISOString();
      if (sessionRow.expires_at < nowIso) return null;
      if (sessionRow.status !== 'ACTIVE') return null;

      // سقف طول عمر مطلق سشن (حداکثر ۳۰ روز از زمان ساخته‌شدن اولیه — L-7 Fix)
      const createdMs = new Date(sessionRow.created_at).getTime();
      const absoluteMaxMs = createdMs + (DEFAULT_CONFIG.SESSION_ABSOLUTE_MAX_AGE_SECONDS * 1000);
      if (Date.now() > absoluteMaxMs) {
        // ابطال قطعی نشست منقضی‌شده به سقف مطلق
        await db.prepare(`UPDATE user_sessions SET revoked_at = ? WHERE id = ?`).bind(nowIso, sessionRow.id).run();
        return null;
      }

      // تمدید لغزان سشن (Sliding Expiration: اگر بیش از ۱ ساعت از آخرین فعالیت گذشته باشد)
      const lastActiveMs = new Date(sessionRow.last_active_at).getTime();
      if (Date.now() - lastActiveMs > 3600000) {
        const maxAge = env.SESSION_MAX_AGE_SECONDS ? parseInt(env.SESSION_MAX_AGE_SECONDS, 10) : DEFAULT_CONFIG.SESSION_MAX_AGE_SECONDS;
        const newExpires = new Date(Math.min(Date.now() + maxAge * 1000, absoluteMaxMs)).toISOString();
        
        const updatePromise = db.prepare(`UPDATE user_sessions SET last_active_at = ?, expires_at = ? WHERE id = ?`)
          .bind(nowIso, newExpires, sessionRow.id).run().catch(() => null);

        if (ctx && typeof ctx.waitUntil === 'function') {
          ctx.waitUntil(updatePromise);
        } else {
          await updatePromise;
        }
      }

      return sessionRow;
    };

    // ========================================================================
    // GET /api/auth/me — استعلام وضعیت هویت، نقش و نشست فعال
    // ========================================================================
    if (url.pathname === '/api/auth/me' && request.method === 'GET') {
      const session = await extractAndValidateSession();
      if (!session) {
        return new Response(JSON.stringify({ authenticated: false }), { status: 401, headers: corsHeaders });
      }

      return new Response(JSON.stringify({
        authenticated: true,
        user: {
          id: session.user_id,
          username: session.username,
          full_name: session.full_name,
          role: session.role,
          status: session.status
        },
        session: {
          id: session.id,
          expires_at: session.expires_at
        }
      }), { status: 200, headers: corsHeaders });
    }

    // ========================================================================
    // POST /api/auth/logout — ابطال آنی نشست در دیتابیس و پاکسازی کوکی
    // ========================================================================
    if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
      const session = await extractAndValidateSession();
      if (session) {
        const nowIso = new Date().toISOString();
        await db.prepare(`UPDATE user_sessions SET revoked_at = ? WHERE id = ?`).bind(nowIso, session.id).run();
        await AuditLogger.record(db, {
          actor_id: session.user_id,
          actor_role: session.role,
          action: 'LOGOUT',
          target_type: 'SESSION',
          target_id: session.id,
          ip_hash: ipHash
        });
      }

      const delCookieHeader = HttpUtils.buildDeleteCookie(isProduction);
      const respHeaders = new Headers(corsHeaders);
      respHeaders.append('Set-Cookie', delCookieHeader);

      return new Response(JSON.stringify({ success: true, message: 'خروج با موفقیت انجام شد.' }), {
        status: 200,
        headers: respHeaders
      });
    }

    // ========================================================================
    // POST /api/auth/change-password — تغییر امن رمز + ابطال سایر نشست‌ها (M-3, M-6, M-9, C-6 Fix)
    // ========================================================================
    if (url.pathname === '/api/auth/change-password' && request.method === 'POST') {
      if (!HttpUtils.checkIpRateLimit(clientIp, 5, 'change_pw')) {
        return new Response(JSON.stringify({ error: 'RATE_LIMITED', message: 'تعداد تلاش برای تغییر رمز بیش از حد مجاز است. لطفاً بعداً تلاش کنید.' }), {
          status: 429,
          headers: corsHeaders
        });
      }

      const session = await extractAndValidateSession();
      if (!session) {
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED', message: 'برای تغییر کلمه عبور ابتدا باید وارد حساب کاربری شوید.' }), {
          status: 401,
          headers: corsHeaders
        });
      }

      try {
        const body = await request.json();
        const currentPassword = String(body.currentPassword || '');
        const newPassword = String(body.newPassword || '');
        const confirmPassword = String(body.confirmPassword || '');

        if (!currentPassword || !newPassword) {
          return new Response(JSON.stringify({ error: 'INVALID_INPUT', message: 'ورود کلمه عبور فعلی و کلمه عبور جدید الزامی است.' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // اعتبارسنجی قدرت کلمه عبور جدید (NIST Policy — M-6 Fix)
        const strengthCheck = CryptoUtils.validatePasswordStrength(newPassword);
        if (!strengthCheck.valid) {
          return new Response(JSON.stringify({ error: 'WEAK_PASSWORD', message: strengthCheck.reason }), {
            status: 400,
            headers: corsHeaders
          });
        }

        if (confirmPassword && newPassword !== confirmPassword) {
          return new Response(JSON.stringify({ error: 'PASSWORD_MISMATCH', message: 'تکرار کلمه عبور جدید با کلمه عبور وارد شده یکسان نیست.' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // واکشی کاربر از دیتابیس D1
        const user = await db.prepare('SELECT id, password_hash, salt, iterations FROM users WHERE id = ?').bind(session.user_id).first();
        if (!user) {
          return new Response(JSON.stringify({ error: 'USER_NOT_FOUND', message: 'کاربر مورد نظر یافت نشد.' }), {
            status: 404,
            headers: corsHeaders
          });
        }

        // اعتبارسنجی کلمه عبور فعلی با PBKDF2
        const iterations = user.iterations || 100000;
        const isCurrentValid = await CryptoUtils.verifyPbkdf2Password(currentPassword, user.salt, user.password_hash, iterations);

        if (!isCurrentValid) {
          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'PASSWORD_CHANGE_FAILED',
            target_type: 'USER',
            target_id: session.user_id,
            ip_hash: ipHash,
            details: { reason: 'INVALID_CURRENT_PASSWORD' }
          });

          return new Response(JSON.stringify({ error: 'INVALID_CURRENT_PASSWORD', message: 'کلمه عبور فعلی وارد شده اشتباه است.' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        // تولید سالت جدید و محاسبه هش جدید
        const newSaltHex = CryptoUtils.bytesToHex(CryptoUtils.getRandomBytes(DEFAULT_CONFIG.SALT_BYTES));
        const newIterations = 100000;
        const newPasswordHash = await CryptoUtils.derivePbkdf2Hash(newPassword, newSaltHex, newIterations);
        const nowIso = new Date().toISOString();

        // به‌روزرسانی جدول users در D1
        await db.prepare(`
          UPDATE users 
          SET password_hash = ?, salt = ?, iterations = ?, metadata_json = json_set(COALESCE(metadata_json, '{}'), '$.password_updated_at', ?)
          WHERE id = ?
        `).bind(newPasswordHash, newSaltHex, newIterations, nowIso, session.user_id).run();

        // ابطال کلیه نشست‌های فعال دیگر کاربر جهت مهار Session Fixation / Hijacking (M-9 Fix)
        await db.prepare(`
          UPDATE user_sessions SET revoked_at = ? WHERE user_id = ? AND id != ?
        `).bind(nowIso, session.user_id, session.id).run();

        // ثبت در لاگ‌های ممیزی
        await AuditLogger.record(db, {
          actor_id: session.user_id,
          actor_role: session.role,
          action: 'PASSWORD_CHANGED',
          target_type: 'USER',
          target_id: session.user_id,
          ip_hash: ipHash,
          details: { updated_at: nowIso }
        });

        return new Response(JSON.stringify({
          success: true,
          message: 'کلمه عبور با موفقیت تغییر یافت و سایر نشست‌های فعال شما جهت امنیت باطل شدند.'
        }), {
          status: 200,
          headers: corsHeaders
        });

      } catch (err) {
        console.error('[ChangePassword Error]:', err);
        return new Response(JSON.stringify({ error: 'INTERNAL_ERROR', message: 'خطای سرور در پردازش تغییر کلمه عبور. لطفاً بعداً تلاش کنید.' }), {
          status: 500,
          headers: corsHeaders
        });
      }
    }

    // ========================================================================
    // POST /api/auth/emergency-break-glass & /api/admin/break-glass/recover-admin (L-2, L-8, M-3 Fix)
    // ========================================================================
    if ((url.pathname === '/api/auth/emergency-break-glass' || url.pathname === '/api/admin/break-glass/recover-admin') && request.method === 'POST') {
      if (!HttpUtils.checkIpRateLimit(clientIp, 3, 'break_glass')) {
        return new Response(JSON.stringify({ error: 'RATE_LIMITED', message: 'تعداد تلاش‌های بازیابی اضطراری بیش از حد مجاز است.' }), {
          status: 429,
          headers: corsHeaders
        });
      }

      const providedSecret = request.headers.get('X-Break-Glass-Secret') || '';
      const serverSecret = env && (env.SUPER_ADMIN_BREAKGLASS_SECRET || env.EMERGENCY_BREAK_GLASS_SECRET);

      const isSecretValid = serverSecret && providedSecret && (await CryptoUtils.timingSafeEqual(providedSecret, serverSecret));

      if (!isSecretValid) {
        await AuditLogger.record(db, {
          actor_role: 'ATTACKER',
          action: 'BREAK_GLASS_UNAUTHORIZED_ATTEMPT',
          ip_hash: ipHash
        });
        return new Response(JSON.stringify({ error: 'UNAUTHORIZED_BREAK_GLASS', message: 'سکرت اضطراری نامعتبر است.' }), {
          status: 403,
          headers: corsHeaders
        });
      }

      try {
        const body = await request.json();
        const targetUsername = (body.targetUsername || 'superadmin').trim().toLowerCase();
        const newPassword = String(body.newPassword || '');

        if (!newPassword || newPassword.length < 12) {
          return new Response(JSON.stringify({ error: 'WEAK_PASSWORD', message: 'رمز عبور اضطراری باید حداقل ۱۲ کاراکتر باشد.' }), {
            status: 400,
            headers: corsHeaders
          });
        }

        const newSalt = CryptoUtils.bytesToHex(CryptoUtils.getRandomBytes(DEFAULT_CONFIG.SALT_BYTES));
        const iterations = env.PBKDF2_ITERATIONS ? parseInt(env.PBKDF2_ITERATIONS, 10) : DEFAULT_CONFIG.PBKDF2_ITERATIONS;
        const newHash = await CryptoUtils.derivePbkdf2Hash(newPassword, newSalt, iterations);
        const nowIso = new Date().toISOString();

        // به‌روزرسانی یا ایجاد حساب سوپرادمین
        const existing = await db.prepare(`SELECT id FROM users WHERE username = ?`).bind(targetUsername).first();
        let targetId = null;

        if (existing) {
          await db.prepare(`
            UPDATE users SET password_hash = ?, salt = ?, iterations = ?, role = 'SUPER_ADMIN', status = 'ACTIVE', failed_login_count = 0, locked_until = NULL WHERE id = ?
          `).bind(newHash, newSalt, iterations, existing.id).run();
          targetId = existing.id;
          // ابطال کلیه سشن‌های قبلی این کاربر
          await db.prepare(`UPDATE user_sessions SET revoked_at = ? WHERE user_id = ?`).bind(nowIso, existing.id).run();
        } else {
          const ins = await db.prepare(`
            INSERT INTO users (username, password_hash, salt, iterations, full_name, role, status, created_at)
            VALUES (?, ?, ?, ?, 'مدیر ارشد سامانه (Super Admin)', 'SUPER_ADMIN', 'ACTIVE', ?)
          `).bind(targetUsername, newHash, newSalt, iterations, nowIso).run();
          targetId = ins.meta ? ins.meta.last_row_id : null;
        }

        // ثبت اجباری در لاگ ممیزی
        await AuditLogger.record(db, {
          actor_role: 'SYSTEM_BREAK_GLASS',
          action: 'EMERGENCY_BREAK_GLASS_RECOVERY',
          target_type: 'USER',
          target_id: targetId,
          ip_hash: ipHash,
          metadata: { username: targetUsername, initiatedAt: nowIso }
        });

        return new Response(JSON.stringify({
          success: true,
          message: 'حساب کاربری ارشد با موفقیت بازیابی شد و کلیه نشست‌های قبلی باطل گردیدند.',
          username: targetUsername
        }), { status: 200, headers: corsHeaders });

      } catch (e) {
        console.error('[BreakGlass Error]:', e);
        return new Response(JSON.stringify({ error: 'BREAK_GLASS_FAILED', message: 'خطا در بازیابی اضطراری.' }), {
          status: 500,
          headers: corsHeaders
        });
      }
    }

    // ========================================================================
    // اندپوینت‌های مدیریتی (Admin Protected Routes — C-1, C-2, C-3, L-10 Fix)
    // ========================================================================
    if (url.pathname.startsWith('/api/admin/')) {
      const session = await extractAndValidateSession();
      if (!session) {
        return new Response(JSON.stringify({ error: 'UNAUTHENTICATED', message: 'احراز هویت الزامی است.' }), {
          status: 401,
          headers: corsHeaders
        });
      }

      if (session.role !== 'ADMIN' && session.role !== 'SUPER_ADMIN' && session.role !== 'ASSISTANT') {
        return new Response(JSON.stringify({ error: 'FORBIDDEN', message: 'دسترسی مجاز نمی‌باشد.' }), {
          status: 403,
          headers: corsHeaders
        });
      }

      // ۱. تایید درخواست عضویت (POST /api/admin/users/approve — C-1 & C-2 & M-7 Fix)
      if (url.pathname === '/api/admin/users/approve' && request.method === 'POST') {
        try {
          const body = await request.json();
          const requestId = parseInt(body.requestId, 10);
          const username = (body.username || '').trim().toLowerCase();
          
          if (!requestId || !username) {
            return new Response(JSON.stringify({ error: 'INVALID_INPUT', message: 'شناسه درخواست و نام کاربری الزامی است.' }), { status: 400, headers: corsHeaders });
          }

          // اعتبارسنجی فرمت نام کاربری (M-7 & L-6 Fix)
          if (!CryptoUtils.validateUsername(username)) {
            return new Response(JSON.stringify({ error: 'INVALID_USERNAME', message: 'نام کاربری باید ۳ تا ۳۲ کاراکتر و فقط شامل حروف انگلیسی، اعداد یا زیرخط باشد.' }), { status: 400, headers: corsHeaders });
          }

          // اعتبارسنجی ماتریس دسترسی جهت جلوگیری از ارتقای دسترسی غیرمجاز (C-2 Fix)
          const requestedRole = (body.role || 'USER').trim().toUpperCase();
          const allowedRolesForActor = ALLOWED_ROLES_BY_ACTOR[session.role] || ['USER'];
          const assignRole = allowedRolesForActor.includes(requestedRole) ? requestedRole : 'USER';

          // مدیریت رمز عبور اولیه: حذف رمز پیش‌فرض هاردکد شده (C-1 Fix)
          let initialPassword = String(body.initialPassword || '').trim();
          let wasPasswordAutoGenerated = false;

          if (!initialPassword) {
            // تولید رمز عبور تصادفی ۱۶ کاراکتری با آنتروپی بالا
            initialPassword = CryptoUtils.generateSecurePassword(16);
            wasPasswordAutoGenerated = true;
          } else {
            // اگر ادمین رمز دستی تعیین کرده، اعتبارسنجی حداقل ۱۲ کاراکتر
            if (initialPassword.length < 12) {
              return new Response(JSON.stringify({ error: 'WEAK_INITIAL_PASSWORD', message: 'رمز عبور اولیه دستی باید حداقل ۱۲ کاراکتر باشد.' }), { status: 400, headers: corsHeaders });
            }
          }

          const reqRow = await db.prepare(`SELECT * FROM membership_requests WHERE id = ?`).bind(requestId).first();
          if (!reqRow) {
            return new Response(JSON.stringify({ error: 'REQUEST_NOT_FOUND', message: 'درخواست عضویت یافت نشد.' }), { status: 404, headers: corsHeaders });
          }

          const salt = CryptoUtils.bytesToHex(CryptoUtils.getRandomBytes(DEFAULT_CONFIG.SALT_BYTES));
          const iterations = env.PBKDF2_ITERATIONS ? parseInt(env.PBKDF2_ITERATIONS, 10) : DEFAULT_CONFIG.PBKDF2_ITERATIONS;
          const passHash = await CryptoUtils.derivePbkdf2Hash(initialPassword, salt, iterations);
          const nowIso = new Date().toISOString();

          // ایجاد کاربر جدید در D1
          const userIns = await db.prepare(`
            INSERT INTO users (username, password_hash, salt, iterations, full_name, contact_info, role, status, created_at, approved_at, approved_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
          `).bind(username, passHash, salt, iterations, reqRow.full_name, reqRow.contact_info, assignRole, nowIso, nowIso, session.user_id).run();

          const newUserId = userIns.meta ? userIns.meta.last_row_id : null;

          // به‌روزرسانی وضعیت درخواست عضویت
          await db.prepare(`UPDATE membership_requests SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ? WHERE id = ?`)
            .bind(session.user_id, nowIso, requestId).run();

          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'APPROVE_USER',
            target_type: 'USER',
            target_id: newUserId,
            ip_hash: ipHash,
            metadata: { username, requestId, assignRole, autoGeneratedPassword: wasPasswordAutoGenerated }
          });

          return new Response(JSON.stringify({
            success: true,
            message: 'کاربر با موفقیت تایید و ایجاد شد.',
            userId: newUserId,
            username,
            role: assignRole,
            initialPassword: wasPasswordAutoGenerated ? initialPassword : undefined
          }), {
            status: 201,
            headers: corsHeaders
          });
        } catch (e) {
          console.error('[ApproveUser Error]:', e);
          const isUniqueError = e.message && e.message.includes('UNIQUE');
          return new Response(JSON.stringify({
            error: 'APPROVE_FAILED',
            message: isUniqueError ? 'این نام کاربری قبلاً ثبت شده است.' : 'خطای سرور در فرآیند تایید کاربر.'
          }), {
            status: 400,
            headers: corsHeaders
          });
        }
      }

      // ۲. تعلیق کاربر و ابطال آنی سشن‌ها با بررسی سلسله‌مراتب نقش‌ها (POST /api/admin/users/suspend — C-3 Fix)
      if (url.pathname === '/api/admin/users/suspend' && request.method === 'POST') {
        if (session.role === 'ASSISTANT') {
          return new Response(JSON.stringify({ error: 'FORBIDDEN', message: 'دستیار اجازه تعلیق کاربران را ندارد.' }), { status: 403, headers: corsHeaders });
        }

        try {
          const body = await request.json();
          const targetUserId = parseInt(body.userId, 10);
          if (!targetUserId || targetUserId === session.user_id) {
            return new Response(JSON.stringify({ error: 'INVALID_TARGET', message: 'شناسه کاربر نامعتبر است یا نمی‌توانید حساب خود را معلق کنید.' }), { status: 400, headers: corsHeaders });
          }

          // استعلام کاربر هدف از پایگاه داده D1
          const targetUser = await db.prepare('SELECT id, username, role, status FROM users WHERE id = ?').bind(targetUserId).first();
          if (!targetUser) {
            return new Response(JSON.stringify({ error: 'USER_NOT_FOUND', message: 'کاربر مورد نظر یافت نشد.' }), { status: 404, headers: corsHeaders });
          }

          // ممانعت قطعی از تعلیق سوپرادمین یا نقش‌های برابر/بالاتر توسط ادمین (C-3 Fix)
          const actorRank = ROLE_RANK[session.role] || 0;
          const targetRank = ROLE_RANK[targetUser.role] || 0;

          if (actorRank <= targetRank && session.role !== 'SUPER_ADMIN') {
            return new Response(JSON.stringify({
              error: 'INSUFFICIENT_PRIVILEGE',
              message: 'شما اجازه تعلیق کاربری با سطح دسترسی برابر یا بالاتر از خود را ندارید.'
            }), { status: 403, headers: corsHeaders });
          }

          const nowIso = new Date().toISOString();
          await db.prepare(`UPDATE users SET status = 'SUSPENDED' WHERE id = ?`).bind(targetUserId).run();
          
          // کلید قطع آنی (Instant Kill-Switch: ابطال کلیه سشن‌های کاربر هدف)
          await db.prepare(`UPDATE user_sessions SET revoked_at = ? WHERE user_id = ?`).bind(nowIso, targetUserId).run();

          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'SUSPEND_USER',
            target_type: 'USER',
            target_id: targetUserId,
            ip_hash: ipHash,
            metadata: { targetUsername: targetUser.username, targetRole: targetUser.role }
          });

          return new Response(JSON.stringify({ success: true, message: 'کاربر تعلیق شد و تمامی نشست‌های فعال وی باطل گردیدند.' }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[SuspendUser Error]:', e);
          return new Response(JSON.stringify({ error: 'SUSPEND_FAILED', message: 'خطا در تعلیق کاربر.' }), { status: 500, headers: corsHeaders });
        }
      }

      // ۳. مشاهده کارتابل درخواست‌های عضویت (GET /api/admin/requests)
      if (url.pathname === '/api/admin/requests' && request.method === 'GET') {
        try {
          const reqs = await db.prepare(`
            SELECT * FROM membership_requests ORDER BY id DESC LIMIT 100
          `).all();
          return new Response(JSON.stringify({ success: true, requests: reqs.results || [] }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[AdminRequests Error]:', e);
          return new Response(JSON.stringify({ error: 'FETCH_FAILED', message: 'خطا در واکشی درخواست‌ها.' }), { status: 500, headers: corsHeaders });
        }
      }

      // ۴. مشاهده لیست کاربران سامانه همراه با ثبت لاگ ممیزی (GET /api/admin/users — L-10 Fix)
      if (url.pathname === '/api/admin/users' && request.method === 'GET') {
        if (session.role === 'ASSISTANT') {
          return new Response(JSON.stringify({ error: 'FORBIDDEN', message: 'دستیار اجازه مشاهده لیست کاربران را ندارد.' }), { status: 403, headers: corsHeaders });
        }
        try {
          const usersList = await db.prepare(`
            SELECT id, username, full_name, contact_info, role, status, failed_login_count, locked_until, created_at, approved_at, last_login_at
            FROM users ORDER BY id DESC LIMIT 200
          `).all();

          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'ADMIN_VIEWED_USERS',
            target_type: 'SYSTEM',
            ip_hash: ipHash
          });

          return new Response(JSON.stringify({ success: true, users: usersList.results || [] }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[AdminUsers Error]:', e);
          return new Response(JSON.stringify({ error: 'FETCH_FAILED', message: 'خطا در واکشی کاربران.' }), { status: 500, headers: corsHeaders });
        }
      }

      // ۵. مشاهده و پاسخ به تیکت‌های پشتیبانی (GET /api/admin/tickets & POST /api/admin/tickets/reply)
      if (url.pathname === '/api/admin/tickets' && request.method === 'GET') {
        try {
          const tickets = await db.prepare(`
            SELECT * FROM support_tickets ORDER BY id DESC LIMIT 100
          `).all();
          return new Response(JSON.stringify({ success: true, tickets: tickets.results || [] }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[AdminTickets Error]:', e);
          return new Response(JSON.stringify({ error: 'FETCH_FAILED', message: 'خطا در واکشی تیکت‌ها.' }), { status: 500, headers: corsHeaders });
        }
      }

      if (url.pathname === '/api/admin/tickets/reply' && request.method === 'POST') {
        try {
          const body = await request.json();
          const ticketId = (body.ticketId || '').trim();
          const replyText = (body.reply || '').trim();
          const newStatus = (body.status || 'RESOLVED').trim();

          if (!ticketId || !replyText) {
            return new Response(JSON.stringify({ error: 'INVALID_INPUT', message: 'شناسه تیکت و متن پاسخ الزامی است.' }), { status: 400, headers: corsHeaders });
          }

          const nowIso = new Date().toISOString();
          await db.prepare(`
            UPDATE support_tickets
            SET admin_response = ?, status = ?, responded_by = ?, responded_at = ?
            WHERE ticket_id = ?
          `).bind(replyText, newStatus, session.user_id, nowIso, ticketId).run();

          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'SUPPORT_TICKET_REPLIED',
            target_type: 'SUPPORT_TICKET',
            target_id: ticketId,
            ip_hash: ipHash
          });

          return new Response(JSON.stringify({ success: true, message: 'پاسخ تیکت با موفقیت ثبت شد.' }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[ReplyTicket Error]:', e);
          return new Response(JSON.stringify({ error: 'REPLY_FAILED', message: 'خطا در ثبت پاسخ تیکت.' }), { status: 500, headers: corsHeaders });
        }
      }

      // ۷. ارتقا یا تغییر نقش کاربر توسط سوپرادمین (POST /api/admin/users/role)
      if (url.pathname === '/api/admin/users/role' && request.method === 'POST') {
        if (session.role !== 'SUPER_ADMIN') {
          return new Response(JSON.stringify({ error: 'FORBIDDEN', message: 'فقط سوپرادمین اجازه تغییر نقش کاربران را دارد.' }), { status: 403, headers: corsHeaders });
        }

        try {
          const body = await request.json();
          const targetUserId = parseInt(body.userId, 10);
          const newRole = (body.role || '').trim().toUpperCase();

          if (!targetUserId || !['USER', 'ASSISTANT', 'ADMIN', 'SUPER_ADMIN'].includes(newRole)) {
            return new Response(JSON.stringify({ error: 'INVALID_INPUT', message: 'شناسه کاربر یا نقش درخواستی نامعتبر است.' }), { status: 400, headers: corsHeaders });
          }

          if (targetUserId === session.user_id && newRole !== 'SUPER_ADMIN') {
            return new Response(JSON.stringify({ error: 'CANNOT_DEMOTE_SELF', message: 'شما نمی‌توانید نقش سوپرادمین خود را تنزل دهید.' }), { status: 400, headers: corsHeaders });
          }

          await db.prepare(`UPDATE users SET role = ? WHERE id = ?`).bind(newRole, targetUserId).run();

          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'USER_ROLE_CHANGED',
            target_type: 'USER',
            target_id: targetUserId,
            ip_hash: ipHash,
            metadata: { newRole }
          });

          return new Response(JSON.stringify({ success: true, message: `نقش کاربر با موفقیت به ${newRole} تغییر یافت.` }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[UserRole Error]:', e);
          return new Response(JSON.stringify({ error: 'ROLE_CHANGE_FAILED', message: 'خطا در تغییر نقش کاربر.' }), { status: 500, headers: corsHeaders });
        }
      }

      // ۸. ارسال پیام سراسری سیستم (POST /api/admin/broadcast)
      if (url.pathname === '/api/admin/broadcast' && request.method === 'POST') {
        if (session.role !== 'SUPER_ADMIN') {
          return new Response(JSON.stringify({ error: 'FORBIDDEN', message: 'فقط سوپرادمین اجازه ارسال پیام سراسری را دارد.' }), { status: 403, headers: corsHeaders });
        }

        try {
          const body = await request.json();
          const message = (body.message || '').trim();
          const level = (body.level || 'INFO').trim();

          if (!message) {
            return new Response(JSON.stringify({ error: 'INVALID_INPUT', message: 'متن پیام سراسری الزامی است.' }), { status: 400, headers: corsHeaders });
          }

          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'SYSTEM_BROADCAST',
            target_type: 'SYSTEM',
            target_id: 'BROADCAST',
            ip_hash: ipHash,
            metadata: { message, level }
          });

          return new Response(JSON.stringify({ success: true, message: 'پیام سراسری با موفقیت ثبت و ارسال شد.' }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[Broadcast Error]:', e);
          return new Response(JSON.stringify({ error: 'BROADCAST_FAILED', message: 'خطا در ارسال پیام سراسری.' }), { status: 500, headers: corsHeaders });
        }
      }

      // ۶. مشاهده لاگ‌های ممیزی همراه با ثبت دسترسی (GET /api/admin/audit-logs — L-10 Fix)
      if (url.pathname === '/api/admin/audit-logs' && request.method === 'GET') {
        if (session.role === 'ASSISTANT') {
          return new Response(JSON.stringify({ error: 'FORBIDDEN', message: 'دستیار اجازه مشاهده لاگ‌های ممیزی را ندارد.' }), { status: 403, headers: corsHeaders });
        }

        try {
          const logs = await db.prepare(`
            SELECT a.*, u.username as actor_username
            FROM audit_logs a
            LEFT JOIN users u ON a.actor_id = u.id
            ORDER BY a.id DESC LIMIT 100
          `).all();

          await AuditLogger.record(db, {
            actor_id: session.user_id,
            actor_role: session.role,
            action: 'ADMIN_VIEWED_AUDIT_LOGS',
            target_type: 'SYSTEM',
            ip_hash: ipHash
          });

          return new Response(JSON.stringify({ success: true, logs: logs.results || [] }), { status: 200, headers: corsHeaders });
        } catch (e) {
          console.error('[AuditLogs Error]:', e);
          return new Response(JSON.stringify({ error: 'FETCH_FAILED', message: 'خطا در واکشی لاگ‌ها.' }), { status: 500, headers: corsHeaders });
        }
      }
    }

    // مسیر پیش‌فرض ۴۰۴
    return new Response(JSON.stringify({ error: 'NOT_FOUND', message: 'اندپوینت مورد نظر در درگاه امنیتی یافت نشد.' }), {
      status: 404,
      headers: corsHeaders
    });
  }
};

// ============================================================
// ۷) اکسپورت استاندارد ماژول Cloudflare Worker
// ============================================================
export {
  CryptoUtils,
  ServiceTrust,
  AuditLogger,
  HttpUtils,
  Worker4Handler,
  DEFAULT_CONFIG,
  ENDPOINT_AUTH_MATRIX,
  ALLOWED_ROLES_BY_ACTOR,
  ROLE_RANK,
  SECURITY_HEADERS
};

export default {
  async fetch(request, env, ctx) {
    return Worker4Handler.handleRequest(request, env, ctx);
  }
};
