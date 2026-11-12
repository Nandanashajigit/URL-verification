
const CONFIG = {
  MAX_SAFE_URL_LENGTH: 75,
  MAX_SAFE_DOMAIN_LENGTH: 30,
  SUSPICIOUS_KEYWORDS: [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "webscr", "password", "suspend", "urgent",
    "click", "free", "bonus", "gift", "unlock", "limited", "alert",
    "recover", "billing", "invoice", "security", "authenticate"
  ],
  SUSPICIOUS_TLDS: [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click",
    "loan", "win", "review", "download", "racing", "party", "faith"
  ],
  URL_SHORTENERS: [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "rebrand.ly"
  ],
  BRAND_KEYWORDS: [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase", "instagram"
  ],
  WEIGHTS: {
    noHttps: 15,
    ipAddress: 25,
    longUrl: 10,
    longDomain: 8,
    suspiciousChars: 15,
    suspiciousKeyword: 12,
    unusualTld: 15,
    manySubdomains: 10,
    redirectCount: 8,        
    urlShortener: 10,
    atSymbol: 20,
    hyphenInDomain: 6,
    brandInSubdomainOrPath: 18,
    punycode: 15,
    portInUrl: 10
  },
  THRESHOLDS: {
    safe: 30,        
    suspicious: 60  
  }
};


function parseUrl(inputUrl) {
  let urlStr = inputUrl.trim();

  let hadProtocol = /^https?:\/\//i.test(urlStr);
  if (!hadProtocol) {
    urlStr = "http://" + urlStr;
  }

  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (err) {
    return { error: "Invalid URL format", raw: inputUrl };
  }

  return {
    raw: inputUrl,
    protocol: parsed.protocol.replace(":", ""),
    hadProtocol,
    hostname: parsed.hostname,          
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search,
    fullUrl: urlStr,
    isHttps: parsed.protocol === "https:"
  };
}


function isIpAddress(hostname) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^\[?[0-9a-fA-F:]+\]?$/;
  if (ipv4.test(hostname)) {
    return hostname.split(".").every(o => Number(o) >= 0 && Number(o) <= 255);
  }
  return hostname.includes(":") && ipv6.test(hostname);
}

function getTld(hostname) {
  const parts = hostname.split(".");
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
}

function countSubdomains(hostname) {
  if (isIpAddress(hostname)) return 0;
  const parts = hostname.split(".");
  return Math.max(0, parts.length - 2);
}

function hasSuspiciousChars(url) {
  const suspiciousPattern = /[<>{}[\]\\^~`]|%00|\.\.\//;
  return suspiciousPattern.test(url);
}

function containsPunycode(hostname) {
  return hostname.includes("xn--");
}

function findKeywordMatches(url) {
  const lower = url.toLowerCase();
  return CONFIG.SUSPICIOUS_KEYWORDS.filter(kw => lower.includes(kw));
}

function findBrandImpersonation(hostname, pathname) {
  const lowerHost = hostname.toLowerCase();
  const lowerPath = pathname.toLowerCase();
  const domainParts = lowerHost.split(".");
  const registrableDomain = domainParts.slice(-2).join(".");

  return CONFIG.BRAND_KEYWORDS.filter(brand => {
    const inHost = lowerHost.includes(brand);
    const inRegistrable = registrableDomain.includes(brand);
    const inPath = lowerPath.includes(brand);
    return (inHost && !inRegistrable) || inPath;
  });
}

function isUrlShortener(hostname) {
  return CONFIG.URL_SHORTENERS.some(s => hostname.toLowerCase() === s);
}



async function countRedirects(url, fetchFn = null) {
  if (!fetchFn) {
    return { count: 0, checked: false };
  }
  try {
    let redirects = 0;
    let currentUrl = url;
    const maxHops = 10;

    for (let i = 0; i < maxHops; i++) {
      const res = await fetchFn(currentUrl);
      if (res.redirected || (res.status >= 300 && res.status < 400)) {
        redirects++;
        currentUrl = res.url || res.headers?.get?.("location");
        if (!currentUrl) break;
      } else {
        break;
      }
    }
    return { count: redirects, checked: true };
  } catch (err) {
    return { count: 0, checked: false, error: err.message };
  }
}


function analyzeUrl(parsedUrl, redirectInfo = { count: 0, checked: false }) {
  const flags = [];
  let score = 0;

  const { fullUrl, hostname, pathname, isHttps, hadProtocol, port } = parsedUrl;

  if (!isHttps) {
    score += CONFIG.WEIGHTS.noHttps;
    flags.push({ check: "HTTPS", detail: "Connection is not encrypted (no HTTPS)", weight: CONFIG.WEIGHTS.noHttps });
  }

  if (isIpAddress(hostname)) {
    score += CONFIG.WEIGHTS.ipAddress;
    flags.push({ check: "IP Address", detail: `Uses raw IP address (${hostname}) instead of a domain name`, weight: CONFIG.WEIGHTS.ipAddress });
  }

  if (fullUrl.length > CONFIG.MAX_SAFE_URL_LENGTH) {
    score += CONFIG.WEIGHTS.longUrl;
    flags.push({ check: "URL Length", detail: `URL is unusually long (${fullUrl.length} chars)`, weight: CONFIG.WEIGHTS.longUrl });
  }

  if (hostname.length > CONFIG.MAX_SAFE_DOMAIN_LENGTH) {
    score += CONFIG.WEIGHTS.longDomain;
    flags.push({ check: "Domain Length", detail: `Domain is unusually long (${hostname.length} chars)`, weight: CONFIG.WEIGHTS.longDomain });
  }

  if (hasSuspiciousChars(fullUrl)) {
    score += CONFIG.WEIGHTS.suspiciousChars;
    flags.push({ check: "Suspicious Characters", detail: "Contains unusual/encoded characters often used to obscure URLs", weight: CONFIG.WEIGHTS.suspiciousChars });
  }

  if (fullUrl.includes("@")) {
    score += CONFIG.WEIGHTS.atSymbol;
    flags.push({ check: "@ Symbol", detail: "Contains '@', which browsers ignore everything before when resolving the host — classic phishing trick", weight: CONFIG.WEIGHTS.atSymbol });
  }

  const keywordMatches = findKeywordMatches(fullUrl);
  if (keywordMatches.length > 0) {
    const weight = CONFIG.WEIGHTS.suspiciousKeyword * Math.min(keywordMatches.length, 3);
    score += weight;
    flags.push({ check: "Suspicious Keywords", detail: `Contains keyword(s): ${keywordMatches.join(", ")}`, weight });
  }

  const tld = getTld(hostname);
  if (CONFIG.SUSPICIOUS_TLDS.includes(tld)) {
    score += CONFIG.WEIGHTS.unusualTld;
    flags.push({ check: "Unusual TLD", detail: `Top-level domain ".${tld}" is commonly abused for phishing`, weight: CONFIG.WEIGHTS.unusualTld });
  }

  if (redirectInfo.checked && redirectInfo.count > 1) {
    const weight = CONFIG.WEIGHTS.redirectCount * (redirectInfo.count - 1);
    score += weight;
    flags.push({ check: "Redirects", detail: `URL redirects ${redirectInfo.count} times before landing`, weight });
  }

  const subdomains = countSubdomains(hostname);
  if (subdomains >= 3) {
    score += CONFIG.WEIGHTS.manySubdomains;
    flags.push({ check: "Excessive Subdomains", detail: `Has ${subdomains} subdomains, often used to disguise the real domain`, weight: CONFIG.WEIGHTS.manySubdomains });
  }

  if (isUrlShortener(hostname)) {
    score += CONFIG.WEIGHTS.urlShortener;
    flags.push({ check: "URL Shortener", detail: "Uses a URL shortening service, which can mask the real destination", weight: CONFIG.WEIGHTS.urlShortener });
  }

  if (!isIpAddress(hostname) && hostname.includes("-")) {
    score += CONFIG.WEIGHTS.hyphenInDomain;
    flags.push({ check: "Hyphenated Domain", detail: "Domain contains hyphens, sometimes used to mimic legitimate brands", weight: CONFIG.WEIGHTS.hyphenInDomain });
  }

  const brandMatches = findBrandImpersonation(hostname, pathname);
  if (brandMatches.length > 0) {
    score += CONFIG.WEIGHTS.brandInSubdomainOrPath;
    flags.push({ check: "Brand Impersonation", detail: `Mentions brand(s) [${brandMatches.join(", ")}] outside the actual domain`, weight: CONFIG.WEIGHTS.brandInSubdomainOrPath });
  }

  if (containsPunycode(hostname)) {
    score += CONFIG.WEIGHTS.punycode;
    flags.push({ check: "Punycode", detail: "Domain uses punycode (xn--), sometimes used for homograph attacks", weight: CONFIG.WEIGHTS.punycode });
  }

  if (port && !["80", "443", ""].includes(port)) {
    score += CONFIG.WEIGHTS.portInUrl;
    flags.push({ check: "Non-standard Port", detail: `Uses non-standard port ${port}`, weight: CONFIG.WEIGHTS.portInUrl });
  }

  score = Math.min(score, 100);

  return { score, flags };
}


function classifyRisk(score) {
  if (score < CONFIG.THRESHOLDS.safe) return "SAFE";
  if (score < CONFIG.THRESHOLDS.suspicious) return "SUSPICIOUS";
  return "DANGEROUS";
}


/**
@param {string} inputUrl
 * @param {object} [options]
 * @param {function} [options.fetchFn] 
 * @returns {Promise<object>}
 */
async function detectPhishing(inputUrl, options = {}) {
  const parsedUrl = parseUrl(inputUrl);

  if (parsedUrl.error) {
    return {
      url: inputUrl,
      valid: false,
      error: parsedUrl.error,
      verdict: "INVALID"
    };
  }

  const redirectInfo = await countRedirects(parsedUrl.fullUrl, options.fetchFn);

  const { score, flags } = analyzeUrl(parsedUrl, redirectInfo);
  const verdict = classifyRisk(score);

  return {
    url: inputUrl,
    normalizedUrl: parsedUrl.fullUrl,
    domain: parsedUrl.hostname,
    valid: true,
    riskScore: score,
    verdict,
    redirects: redirectInfo,
    flags,
    checkedAt: new Date().toISOString()
  };
}


module.exports = {
  detectPhishing,
  analyzeUrl,
  parseUrl,
  classifyRisk,
  CONFIG
};


if (require.main === module) {
  const testUrls = [
    "https://www.google.com",
    "http://192.168.1.1/login/secure-verify",
    "https://paypal.com.account-verify-login.tk/webscr",
    "http://bit.ly/3xample",
    "https://accounts.google.com/signin",
    "http://user@fake-bank.com/login",
    "https://xn--pypal-4ve.com/verify-account-update"
  ];

  (async () => {
    for (const url of testUrls) {
      const result = await detectPhishing(url);
      console.log("\n=====================================");
      console.log("URL:      ", result.url);
      console.log("Verdict:  ", result.verdict, `(score: ${result.riskScore})`);
      if (result.flags && result.flags.length) {
        console.log("Flags:");
        result.flags.forEach(f => console.log(`  - [${f.check}] ${f.detail} (+${f.weight})`));
      }
    }
  })();
}