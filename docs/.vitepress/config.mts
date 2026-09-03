import { defineConfig } from 'vitepress'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const repo = 'https://github.com/fabriziosalmi/caddy-waf'
const site = 'https://www.caddy-waf.com/'

// Read the version straight out of the source rather than hard-coding it here,
// so the number shown in the nav cannot drift from the module it documents.
// Failing loudly is deliberate: a silent fallback would ship wrong docs.
const wafVersion = (() => {
  const src = readFileSync(
    fileURLToPath(new URL('../../caddywaf.go', import.meta.url)),
    'utf8',
  )
  const m = src.match(/wafVersion\s*=\s*"(v[^"]+)"/)
  if (!m) throw new Error('could not read wafVersion from caddywaf.go')
  return m[1]
})()

export default defineConfig({
  title: 'caddy-waf',
  description:
    'Web Application Firewall middleware for Caddy — regex rule engine with anomaly scoring, IP/DNS/ASN/country blacklists, rate limiting, and a JSON metrics endpoint.',
  lang: 'en-US',

  // Served from the custom domain https://www.caddy-waf.com/ (CNAME in docs/public),
  // so the site lives at the root: base must be '/', not the old project subpath.
  base: '/',

  // Fail the build on a link to a page that does not exist, so the docs cannot
  // drift from the file tree unnoticed.
  ignoreDeadLinks: false,

  cleanUrls: true,
  lastUpdated: true,

  sitemap: { hostname: site },

  markdown: {
    // Shiki ships no Caddyfile grammar. nginx is the closest fit -- directive,
    // arguments, braces, '#' comments -- and the docs carry 13 Caddyfile
    // blocks, so falling back to plain text would cost real legibility.
    languageAlias: {
      caddyfile: 'nginx',
      cron: 'bash',
    },
    // Note: the single ```promql block in prometheus.md falls back to plain
    // text with a build warning. Shiki bundles no PromQL grammar and nothing
    // else is close enough to be worth aliasing.
  },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/logo.svg' }],
    ['link', { rel: 'icon', type: 'image/png', sizes: '32x32', href: '/favicon-32.png' }],
    ['link', { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' }],
    ['meta', { name: 'theme-color', content: '#0369a1' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:site_name', content: 'caddy-waf' }],
    ['meta', { property: 'og:title', content: 'caddy-waf — Web Application Firewall for Caddy' }],
    [
      'meta',
      {
        property: 'og:description',
        content:
          'Regex rule engine with anomaly scoring, blacklists, geo and ASN filtering, and rate limiting. Registered Caddy module http.handlers.waf.',
      },
    ],
    // Absolute URL: relative og:image values are not resolved by most crawlers.
    // PNG rather than SVG, which several of them refuse to render.
    ['meta', { property: 'og:image', content: `${site}og.png` }],
    ['meta', { property: 'og:image:width', content: '1200' }],
    ['meta', { property: 'og:image:height', content: '630' }],
    ['meta', { property: 'og:url', content: site }],
    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:image', content: `${site}og.png` }],
  ],

  themeConfig: {
    logo: '/logo.svg',

    // Client-side index. No external search service is contacted, which keeps
    // the published site free of third-party requests.
    search: { provider: 'local' },

    nav: [
      { text: 'Introduction', link: '/introduction' },
      { text: 'Installation', link: '/installation' },
      { text: 'Configuration', link: '/configuration' },
      {
        // Tells the reader which build these pages describe -- the install
        // instructions and the security notes are both version-sensitive.
        text: wafVersion,
        items: [
          { text: 'Release notes', link: `${repo}/releases/tag/${wafVersion}` },
          { text: 'Changelog', link: `${repo}/blob/main/CHANGELOG.md` },
          { text: 'All releases', link: `${repo}/releases` },
          {
            text: 'Caddy module page',
            link: 'https://caddyserver.com/docs/modules/http.handlers.waf',
          },
          { text: 'Security advisories', link: `${repo}/security/advisories` },
        ],
      },
    ],

    sidebar: [
      {
        text: 'Getting started',
        collapsed: false,
        items: [
          { text: 'Introduction', link: '/introduction' },
          { text: 'Installation', link: '/installation' },
          { text: 'caddy add-package', link: '/add-package-guide' },
          { text: 'Docker', link: '/docker' },
        ],
      },
      {
        text: 'Configuration',
        collapsed: false,
        items: [
          { text: 'Directives and JSON fields', link: '/configuration' },
          { text: 'Rules', link: '/rules' },
          { text: 'Blacklists', link: '/blacklists' },
          { text: 'Rate limiting', link: '/ratelimit' },
          { text: 'Country and ASN blocking', link: '/geoblocking' },
          { text: 'Client IP & trusted proxies', link: '/client-ip' },
          { text: 'Dynamic updates', link: '/dynamicupdates' },
        ],
      },
      {
        text: 'Observability',
        collapsed: false,
        items: [
          { text: 'Dashboard', link: '/dashboard' },
          { text: 'Metrics', link: '/metrics' },
          { text: 'Prometheus and Grafana', link: '/prometheus' },
          { text: 'ELK', link: '/caddy-waf-elk' },
        ],
      },
      {
        text: 'Reference',
        collapsed: false,
        items: [
          { text: 'Attack coverage', link: '/attacks' },
          { text: 'Testing', link: '/testing' },
          { text: 'Traffic generator', link: '/caddytest' },
          { text: 'Helper scripts', link: '/scripts' },
        ],
      },
    ],

    socialLinks: [{ icon: 'github', link: repo }],

    editLink: {
      pattern: `${repo}/edit/main/docs/:path`,
      text: 'Edit this page on GitHub',
    },

    outline: { level: [2, 3] },

    footer: {
      message: `Released under the AGPL-3.0 licence. <a href="${repo}/security/advisories">Security advisories</a>.`,
      copyright: `Copyright © ${new Date().getFullYear()} Fabrizio Salmi`,
    },
  },
})
