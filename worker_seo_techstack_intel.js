const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-RapidAPI-Key, X-RapidAPI-Host, X-RapidAPI-Proxy-Secret',
  'Access-Control-Max-Age': '86400',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS_HEADERS,
    },
  });
}

const TECH_SIGNATURES = [
  { name: 'Next.js', category: 'Framework', html: /_next\/static|__NEXT_DATA__/i, header: ['x-powered-by', /next\.js/i] },
  { name: 'Nuxt.js', category: 'Framework', html: /_nuxt\/|__NUXT__/i },
  { name: 'React', category: 'Frontend', html: /data-reactroot|react-dom/i },
  { name: 'Vue.js', category: 'Frontend', html: /data-v-[a-f0-9]{6,}|vue\.runtime/i },
  { name: 'SvelteKit', category: 'Framework', html: /__sveltekit/i },
  { name: 'Astro', category: 'Framework', html: /astro-island/i },
  { name: 'WordPress', category: 'CMS', html: /wp-content\/|wp-includes\//i },
  { name: 'Shopify', category: 'E-Commerce', html: /cdn\.shopify\.com|Shopify\.theme/i },
  { name: 'Webflow', category: 'CMS', html: /data-wf-site|webflow\.js/i },
  { name: 'Framer', category: 'CMS', html: /framerusercontent\.com/i },
  { name: 'Ghost', category: 'CMS', html: /content="Ghost\s/i },
  { name: 'Tailwind CSS', category: 'CSS', html: /class="[^"]*\b(flex|grid|bg-|text-|px-|py-)[^"]*"/i },
  { name: 'Google Analytics 4', category: 'Analytics', html: /googletagmanager\.com\/gtag\/js|G-[A-Z0-9]{8,}/i },
  { name: 'Google Tag Manager', category: 'Analytics', html: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]{5,}/i },
  { name: 'Segment', category: 'Analytics', html: /cdn\.segment\.com\/analytics\.js/i },
  { name: 'PostHog', category: 'Analytics', html: /app\.posthog\.com|us\.i\.posthog\.com/i },
  { name: 'Plausible', category: 'Analytics', html: /plausible\.io\/js\/script/i },
  { name: 'Mixpanel', category: 'Analytics', html: /cdn\.mxpnl\.com/i },
  { name: 'HubSpot', category: 'CRM & Marketing', html: /js\.hs-scripts\.com|js\.hsforms\.net/i },
  { name: 'Intercom', category: 'Customer Support', html: /widget\.intercom\.io/i },
  { name: 'Crisp', category: 'Customer Support', html: /client\.crisp\.chat/i },
  { name: 'Zendesk', category: 'Customer Support', html: /static\.zdassets\.com/i },
  { name: 'Stripe', category: 'Payments', html: /js\.stripe\.com/i },
  { name: 'Paddle', category: 'Payments', html: /cdn\.paddle\.com/i },
  { name: 'Sentry', category: 'Monitoring', html: /browser\.sentry-cdn\.com|sentry\.io/i },
  { name: 'Cloudflare', category: 'CDN & Edge', header: ['server', /cloudflare/i] },
  { name: 'Vercel', category: 'Hosting', header: ['server', /vercel/i] },
  { name: 'Netlify', category: 'Hosting', header: ['server', /netlify/i] },
];

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];

function extractMeta(html, attrName, attrValue) {
  const re1 = new RegExp(`<meta[^>]+${attrName}=["']${attrValue}["'][^>]+content=["']([^"']*)["']`, 'i');
  const re2 = new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+${attrName}=["']${attrValue}["']`, 'i');
  return (html.match(re1)?.[1] || html.match(re2)?.[1] || null);
}

async function analyzeUrl(targetUrl) {
  const normalizedUrl = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
  const start = Date.now();
  const resp = await fetch(normalizedUrl, {
    redirect: 'follow',
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; SEOTechStackAuditBot/1.0; +https://rapidapi.com)',
      'Accept': 'text/html,application/xhtml+xml',
    },
  });
  const ttfbMs = Date.now() - start;
  const html = await resp.text();
  const headersObj = {};
  resp.headers.forEach((v, k) => {
    headersObj[k.toLowerCase()] = v;
  });

  // Title, Description, Canonical
  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || '').replace(/\s+/g, ' ').trim();
  const description = extractMeta(html, 'name', 'description');
  const robots = extractMeta(html, 'name', 'robots');
  const viewport = extractMeta(html, 'name', 'viewport');
  const canonical = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i)?.[1] || null;

  // OpenGraph & Twitter
  const openGraph = {
    title: extractMeta(html, 'property', 'og:title'),
    description: extractMeta(html, 'property', 'og:description'),
    image: extractMeta(html, 'property', 'og:image'),
    type: extractMeta(html, 'property', 'og:type'),
    site_name: extractMeta(html, 'property', 'og:site_name'),
  };
  const twitterCard = {
    card: extractMeta(html, 'name', 'twitter:card'),
    title: extractMeta(html, 'name', 'twitter:title'),
    image: extractMeta(html, 'name', 'twitter:image'),
  };

  // Headings
  const h1s = [...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)].map((m) => m[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim()).filter(Boolean);
  const h2s = [...html.matchAll(/<h2[^>]*>([\s\S]*?)<\/h2>/gi)].map((m) => m[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim()).filter(Boolean);

  // Images & alt audit
  const imgTags = [...html.matchAll(/<img\b[^>]*>/gi)].map((m) => m[0]);
  const imgsMissingAlt = imgTags.filter((tag) => !/\balt=["'][^"']+["']/i.test(tag)).length;

  // JSON-LD Schema types
  const schemaTypes = [];
  for (const m of html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)) {
    try {
      const parsed = JSON.parse(m[1].trim());
      const items = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of items) {
        if (item?.['@type']) schemaTypes.push(item['@type']);
      }
    } catch {
      // ignore invalid JSON-LD
    }
  }

  // Tech Stack Detection
  const detectedTech = [];
  for (const sig of TECH_SIGNATURES) {
    let matched = false;
    if (sig.html && sig.html.test(html)) matched = true;
    if (!matched && sig.header) {
      const [hName, hRegex] = sig.header;
      if (headersObj[hName] && hRegex.test(headersObj[hName])) matched = true;
    }
    if (matched) {
      detectedTech.push({ name: sig.name, category: sig.category });
    }
  }

  // Security Headers Score
  const securityPresent = {};
  let secCount = 0;
  for (const h of SECURITY_HEADERS) {
    const has = Boolean(headersObj[h]);
    securityPresent[h] = headersObj[h] || null;
    if (has) secCount++;
  }

  // SEO Score (0-100)
  let seoScore = 0;
  const issues = [];
  if (title.length >= 10 && title.length <= 70) seoScore += 20;
  else issues.push('Title tag missing or outside optimal 10-70 char range');
  if (description && description.length >= 50 && description.length <= 170) seoScore += 20;
  else issues.push('Meta description missing or outside optimal 50-170 char range');
  if (canonical) seoScore += 15;
  else issues.push('Missing canonical link tag');
  if (h1s.length === 1) seoScore += 15;
  else issues.push(`Expected exactly 1 H1 tag, found ${h1s.length}`);
  if (viewport) seoScore += 10;
  else issues.push('Missing mobile viewport meta tag');
  if (openGraph.title && openGraph.image) seoScore += 10;
  else issues.push('Incomplete OpenGraph tags (og:title / og:image)');
  if (imgTags.length === 0 || imgsMissingAlt === 0) seoScore += 10;
  else issues.push(`${imgsMissingAlt} of ${imgTags.length} images missing alt attributes`);

  return {
    url: resp.url,
    status_code: resp.status,
    ttfb_ms: ttfbMs,
    seo_score: seoScore,
    seo_issues: issues,
    metadata: {
      title,
      title_length: title.length,
      description,
      description_length: description ? description.length : 0,
      canonical,
      robots,
      viewport,
      open_graph: openGraph,
      twitter_card: twitterCard,
    },
    content_structure: {
      h1_count: h1s.length,
      h1_tags: h1s.slice(0, 5),
      h2_count: h2s.length,
      h2_tags: h2s.slice(0, 10),
      total_images: imgTags.length,
      images_missing_alt: imgsMissingAlt,
      schema_org_types: schemaTypes.flat(),
    },
    technologies: detectedTech,
    security_headers: {
      score_out_of_6: secCount,
      headers: securityPresent,
    },
    audited_at: new Date().toISOString(),
  };
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });
    if (env.RAPIDAPI_PROXY_SECRET) {
      const incoming = request.headers.get('X-RapidAPI-Proxy-Secret');
      if (incoming !== env.RAPIDAPI_PROXY_SECRET) {
        return jsonResponse({ error: 'Unauthorized RapidAPI Proxy Secret' }, 403);
      }
    }

    const reqUrl = new URL(request.url);
    if (reqUrl.pathname === '/' || reqUrl.pathname === '/v1/health') {
      return jsonResponse({ status: 'healthy', service: 'seo-techstack-intel-api', version: '1.0.0' });
    }

    if (reqUrl.pathname === '/v1/audit' || reqUrl.pathname === '/v1/techstack') {
      let targetUrl = reqUrl.searchParams.get('url') || '';
      if (!targetUrl && request.method === 'POST') {
        try {
          const body = await request.json();
          targetUrl = body.url || '';
        } catch {
          targetUrl = '';
        }
      }
      if (!targetUrl) {
        return jsonResponse({ error: 'Missing required parameter: url' }, 400);
      }
      try {
        const report = await analyzeUrl(targetUrl);
        return jsonResponse(report, 200);
      } catch (err) {
        return jsonResponse({ error: 'Failed to fetch target URL', details: err.message }, 502);
      }
    }

    return jsonResponse({ error: 'Not Found', endpoints: ['/v1/audit', '/v1/techstack', '/v1/health'] }, 404);
  },
};
