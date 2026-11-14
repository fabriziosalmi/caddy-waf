"""Generate the README diagram (light and dark) for caddy-waf.

Every label states what handler.go does, in the order it does it. Regenerate
after changing the request pipeline:

    python3 tools/diagram/how_it_works.py docs/public
"""
import sys
from xml.sax.saxutils import escape

W, H = 1000, 584
FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

PALETTES = {
    "light": dict(text="#1f2328", muted="#59636e", line="#d1d9e0", box="#f6f8fa",
                  frame="#ffffff", accent="#0969da", accent_bg="#ddf4ff",
                  block="#cf222e", block_bg="#ffebe9", arrow="#59636e"),
    "dark": dict(text="#f0f6fc", muted="#9198a1", line="#3d444d", box="#151b23",
                 frame="#0d1117", accent="#4493f8", accent_bg="#0d2847",
                 block="#f85149", block_bg="#3c1618", arrow="#9198a1"),
}


def t(x, y, s, size=13, weight=400, fill="text", anchor="start", family=FONT, p=None):
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
            f'font-weight="{weight}" fill="{p[fill]}" text-anchor="{anchor}">{escape(s)}</text>')


def box(x, y, w, h, p, fill="box", stroke="line", rx=10, sw=1):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
            f'fill="{p[fill]}" stroke="{p[stroke]}" stroke-width="{sw}"/>')


def arrow(points, p, color="arrow", dashed=False):
    d = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}" for i, (x, y) in enumerate(points))
    dash = ' stroke-dasharray="4 4"' if dashed else ""
    return (f'<path d="{d}" fill="none" stroke="{p[color]}" stroke-width="1.5"{dash} '
            f'marker-end="url(#arrow-{color})"/>')


def render(name):
    p = PALETTES[name]
    o = []
    o.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
             f'viewBox="0 0 {W} {H}" role="img" aria-labelledby="title desc">')
    o.append('<title id="title">How caddy-waf inspects a request</title>')
    o.append('<desc id="desc">caddy-waf runs inside Caddy. Phase 1 checks the client '
             'against an IP allowlist, IP and DNS blacklists, a rate limit and country '
             'and ASN lists, then runs rules on the URL and headers. Phase 2 runs rules '
             'on the request body. Matching rules add to an anomaly score; at the '
             'threshold, or on a rule with action block, the request is answered with '
             '403 and never reaches the application. Phases 3 and 4 run rules on the '
             'response headers and body before the response returns to the client.</desc>')
    o.append('<defs>')
    for c in ("arrow", "accent", "block"):
        o.append(f'<marker id="arrow-{c}" viewBox="0 0 10 10" refX="9" refY="5" '
                 f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                 f'<path d="M0,0 L10,5 L0,10 z" fill="{p[c]}"/></marker>')
    o.append('</defs>')

    # Caddy frame
    fx, fy, fw, fh = 150, 14, 670, 556
    o.append(box(fx, fy, fw, fh, p, fill="frame", rx=14, sw=1.5))
    o.append(t(fx + 20, fy + 30, "Caddy", 15, 600, p=p))
    o.append(t(fx + 72, fy + 30, "waf handler (http.handlers.waf), inside your route", 12,
               fill="muted", p=p))

    # Client and app
    o.append(box(16, 110, 110, 48, p, rx=24))
    o.append(t(71, 139, "Client", 14, 600, anchor="middle", p=p))
    o.append(box(846, 110, 138, 48, p, rx=10))
    o.append(t(915, 132, "Your app", 14, 600, anchor="middle", p=p))
    o.append(t(915, 149, "reverse_proxy, files", 11, fill="muted", anchor="middle", p=p))

    # Lane labels
    o.append(t(fx + 20, 76, "REQUEST", 11, 600, fill="muted", p=p))
    o.append(t(fx + 20, 404, "RESPONSE", 11, 600, fill="muted", p=p))

    # Phase 1
    x1, y1, w1, h1 = 170, 88, 330, 284
    o.append(box(x1, y1, w1, h1, p))
    o.append(t(x1 + 16, y1 + 26, "Phase 1", 14, 600, fill="accent", p=p))
    o.append(t(x1 + 78, y1 + 26, "who is asking, and for what", 12, fill="muted", p=p))
    items = [
        ("IP allowlist", "skips checks 2 and 5"),
        ("IP blacklist", "peer and X-Forwarded-For"),
        ("DNS blacklist", "Host header"),
        ("Rate limit", "per client IP, 429"),
        ("Country, ASN", "MaxMind GeoLite2"),
        ("Rules", "URL, query, headers, cookies"),
    ]
    for i, (label, detail) in enumerate(items):
        cy = y1 + 62 + i * 36
        o.append(f'<circle cx="{x1 + 26}" cy="{cy - 4}" r="10" fill="{p["accent_bg"]}"/>')
        o.append(t(x1 + 26, cy, str(i + 1), 11, 600, fill="accent", anchor="middle", p=p))
        o.append(t(x1 + 44, cy, label, 13, 600, p=p))
        o.append(t(x1 + 150, cy, detail, 12, fill="muted", p=p))
    o.append(t(x1 + 16, y1 + h1 - 16, "A hit on 2, 3 or 5 is answered 403 at once.", 12,
               fill="block", p=p))

    # Phase 2
    x2, y2, w2, h2 = 520, 88, 280, 92
    o.append(box(x2, y2, w2, h2, p))
    o.append(t(x2 + 16, y2 + 26, "Phase 2", 14, 600, fill="accent", p=p))
    o.append(t(x2 + 78, y2 + 26, "request body", 12, fill="muted", p=p))
    o.append(t(x2 + 16, y2 + 52, "Rules on the body, JSON fields", 13, p=p))
    o.append(t(x2 + 16, y2 + 72, "and uploaded file names", 13, p=p))

    # Anomaly score
    xs, ys, ws, hs = 520, 200, 280, 172
    o.append(box(xs, ys, ws, hs, p, fill="block_bg", stroke="block"))
    o.append(t(xs + 16, ys + 26, "Anomaly score", 14, 600, fill="block", p=p))
    for i, line in enumerate([
        "Each matching rule adds its score.",
        "Blocked when the total reaches",
        "anomaly_threshold, or at once when",
        "the rule's action is block.",
    ]):
        o.append(t(xs + 16, ys + 52 + i * 20, line, 13, p=p))
    o.append(t(xs + 16, ys + 148, "403, and your app never sees it", 13, 600, fill="block", p=p))

    # Phase 3 and 4 (response lane, right to left)
    x3, y3, w3, h3 = 520, 416, 280, 70
    o.append(box(x3, y3, w3, h3, p))
    o.append(t(x3 + 16, y3 + 26, "Phase 3", 14, 600, fill="accent", p=p))
    o.append(t(x3 + 78, y3 + 26, "response headers", 12, fill="muted", p=p))
    o.append(t(x3 + 16, y3 + 50, "Rules on the headers your app sends", 13, p=p))
    x4, y4, w4, h4 = 170, 416, 330, 70
    o.append(box(x4, y4, w4, h4, p))
    o.append(t(x4 + 16, y4 + 26, "Phase 4", 14, 600, fill="accent", p=p))
    o.append(t(x4 + 78, y4 + 26, "response body", 12, fill="muted", p=p))
    o.append(t(x4 + 16, y4 + 50, "Rules on the body your app sends", 13, p=p))

    o.append(t(x4, y4 + h4 + 24,
               "A blocking match in phase 3 or 4 replaces the response with the block response.",
               12, fill="block", p=p))

    # Observability footer
    o.append(t(fx + 20, fy + fh - 18,
               "Visible in /waf_metrics (JSON), Prometheus, the built-in dashboard and JSON logs",
               12, fill="muted", p=p))

    # Flow arrows
    o.append(arrow([(126, 134), (168, 134)], p))                     # client -> phase 1
    o.append(arrow([(500, 134), (518, 134)], p))                     # phase 1 -> phase 2
    o.append(arrow([(800, 134), (844, 134)], p))                     # phase 2 -> app
    o.append(arrow([(660, 180), (660, 198)], p, color="block", dashed=True))  # phase 2 -> score
    o.append(arrow([(500, 326), (518, 326)], p, color="block", dashed=True))  # phase 1 rules -> score
    o.append(arrow([(915, 158), (915, 451), (802, 451)], p))         # app -> phase 3
    o.append(arrow([(520, 451), (502, 451)], p))                     # phase 3 -> phase 4
    o.append(arrow([(170, 451), (71, 451), (71, 160)], p))           # phase 4 -> client

    o.append('</svg>')
    return "\n".join(o) + "\n"


if __name__ == "__main__":
    out = sys.argv[1]
    for name in PALETTES:
        with open(f"{out}/how-it-works-{name}.svg", "w") as f:
            f.write(render(name))
