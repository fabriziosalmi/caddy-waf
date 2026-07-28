/*
 * Validate in-page anchors across docs/.
 *
 * VitePress fails the build on a link to a page that does not exist, but it
 * does not check the #fragment. A link to a real page with a stale anchor
 * therefore ships silently and lands the reader at the top of the page with no
 * indication anything is wrong -- which is exactly how
 * installation.md#option-1-... survived review and a green build, the headings
 * there being "Method N" and not "Option N".
 *
 * Runs automatically before `npm run docs:build` via the npm pre-script hook,
 * so it guards CI and local builds alike.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join, basename } from 'node:path'
import { fileURLToPath } from 'node:url'

const DOCS = fileURLToPath(new URL('..', import.meta.url))

/** GitHub/VitePress heading slug: strip markup, lowercase, spaces to hyphens,
 *  drop everything else. An em dash vanishes, which is why "A — B" yields
 *  "a--b" with a double hyphen. */
function slug(heading) {
  return [
    ...heading
      .replace(/`([^`]*)`/g, '$1')
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      .trim()
      .toLowerCase(),
  ]
    .map((ch) => (/[\p{L}\p{N}\-_]/u.test(ch) ? ch : /\s/.test(ch) ? '-' : ''))
    .join('')
}

const files = readdirSync(DOCS).filter((f) => f.endsWith('.md'))

const headings = new Map(
  files.map((f) => [
    f,
    new Set(
      readFileSync(join(DOCS, f), 'utf8')
        .split('\n')
        .flatMap((l) => {
          const m = l.match(/^#{1,6}\s+(.*)$/)
          return m ? [slug(m[1])] : []
        }),
    ),
  ]),
)

const problems = []
const linkRe = /\]\(([^)\s]*?)#([^)\s]+)\)/g

for (const file of files) {
  const lines = readFileSync(join(DOCS, file), 'utf8').split('\n')
  lines.forEach((line, i) => {
    for (const [, target, anchor] of line.matchAll(linkRe)) {
      if (/^https?:/.test(target)) continue
      const dest = target === '' ? file : basename(target)
      // Only pages inside docs/ can be checked; links out to the repo cannot.
      if (!headings.has(dest)) continue
      if (!headings.get(dest).has(anchor)) {
        problems.push({ file, line: i + 1, target: target || dest, anchor, dest })
      }
    }
  })
}

if (problems.length) {
  console.error(`\n${problems.length} broken anchor link(s):\n`)
  for (const p of problems) {
    const near = [...headings.get(p.dest)]
      .filter((h) => h.split('-').pop() === p.anchor.split('-').pop())
      .slice(0, 3)
    console.error(`  ${p.file}:${p.line}  ->  ${p.target}#${p.anchor}`)
    if (near.length) console.error(`      did you mean: ${near.join(', ')}`)
  }
  console.error('')
  process.exit(1)
}

console.log(`anchors ok (${files.length} pages)`)
