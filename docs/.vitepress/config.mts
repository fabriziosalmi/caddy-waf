import { defineConfig } from 'vitepress'

const repo = 'https://github.com/fabriziosalmi/caddy-waf'

export default defineConfig({
  title: 'caddy-waf',
  description:
    'Web Application Firewall middleware for Caddy — regex rule engine with anomaly scoring, IP/DNS/ASN/country blacklists, rate limiting, and a JSON metrics endpoint.',
  lang: 'en-US',

  // Project page, served from https://fabriziosalmi.github.io/caddy-waf/
  base: '/caddy-waf/',

  // Fail the build on a link to a page that does not exist, so the docs cannot
  // drift from the file tree unnoticed.
  ignoreDeadLinks: false,

  cleanUrls: true,
  lastUpdated: true,

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
    ['meta', { name: 'theme-color', content: '#22a2f2' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'caddy-waf' }],
    [
      'meta',
      {
        property: 'og:description',
        content: 'Web Application Firewall middleware for Caddy.',
      },
    ],
  ],

  themeConfig: {
    // Client-side index. No external search service is contacted, which keeps
    // the published site free of third-party requests.
    search: { provider: 'local' },

    nav: [
      { text: 'Introduction', link: '/introduction' },
      { text: 'Installation', link: '/installation' },
      { text: 'Configuration', link: '/configuration' },
      {
        text: 'Links',
        items: [
          { text: 'GitHub', link: repo },
          { text: 'Releases', link: `${repo}/releases` },
          { text: 'Changelog', link: `${repo}/blob/main/CHANGELOG.md` },
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
          { text: 'Dynamic updates', link: '/dynamicupdates' },
        ],
      },
      {
        text: 'Observability',
        collapsed: false,
        items: [
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
