// Pure helpers for qa/sdk.mjs: find the README quick start a new user copies first and judge
// its output. Kept apart from the script so they can be tested without network or installs.

/** The first fenced block in the README's quick start whose language is one of `fences`. */
export function extractQuickstart(readme, fences) {
  const start = readme.indexOf('## Quick start')
  if (start < 0) return undefined
  const section = readme.slice(start)
  const block = /```([\w-]*)\n([\s\S]*?)```/g
  for (const match of section.matchAll(block)) if (fences.includes(match[1])) return match[2]
}

/** Rust snippets without their own `fn main` are wrapped in a fallible one, as a reader would. */
export function rustMain(code) {
  return /\bfn main\b/.test(code) ? code : `fn main() -> Result<(), Box<dyn std::error::Error>> {\n${code}\nOk(())\n}\n`
}

/** The decisions the README promises the quick start prints, e.g. "prints `allow` ... `block`". */
export function promisedDecisions(readme) {
  const start = readme.indexOf('## Quick start')
  if (start < 0) return []
  const section = readme.slice(start)
  const end = section.indexOf('\n## ', 1)
  const text = end < 0 ? section : section.slice(0, end)
  const sentence = /prints?\s+([^.]*)/i.exec(text.replace(/```[\s\S]*?```/g, ''))?.[1] ?? ''
  return [...sentence.matchAll(/`(allow|warn|block|review)`/g)].map(match => match[1])
}

/** Decisions the README promises that the run's stdout does not show (in order of appearance). */
export function missingDecisions(stdout, promised) {
  const lines = stdout.split('\n')
  const missing = []
  let from = 0
  for (const decision of promised) {
    const index = lines.findIndex((line, i) => i >= from && new RegExp(`\\b${decision}\\b`).test(line))
    if (index < 0) missing.push(decision)
    else from = index + 1
  }
  return missing
}
