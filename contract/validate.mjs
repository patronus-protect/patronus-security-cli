#!/usr/bin/env node
// Validates the shared response fixtures against the pinned OpenAPI document (contract/openapi.json).
// Node built-ins only; implements the JSON Schema subset the published document uses and
// rejects any other keyword so an unsupported construct can never pass silently.
//
//   node contract/validate.mjs
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = new URL('./', import.meta.url)

/** Fixture file -> component schema it must satisfy. */
export const fixtures = {
  'completed.json': 'CompletedSubmission',
  'completed-injection.json': 'CompletedSubmission',
  'completed-flat.json': 'Job',
  'quota-monthly-limit.json': 'Error',
}

const annotations = new Set(['description', 'default', 'example', 'examples', 'format', 'title', 'deprecated'])
const typeOf = value => value === null ? 'null' : Array.isArray(value) ? 'array'
  : typeof value === 'number' ? (Number.isInteger(value) ? 'integer' : 'number') : typeof value

export function validate(spec, schema, value, path = '$') {
  const errors = []
  const fail = message => errors.push(`${path}: ${message}`)
  if (schema.$ref) {
    const name = /^#\/components\/schemas\/(.+)$/.exec(schema.$ref)?.[1]
    if (!name || !spec.components.schemas[name]) return [`${path}: unresolvable $ref ${schema.$ref}`]
    errors.push(...validate(spec, spec.components.schemas[name], value, path))
  }
  for (const [keyword, expected] of Object.entries(schema)) {
    if (annotations.has(keyword) || keyword === '$ref') continue
    const type = typeOf(value)
    switch (keyword) {
      case 'type': {
        const types = [expected].flat()
        if (!types.some(name => name === type || (name === 'number' && type === 'integer'))) fail(`expected ${types.join('|')}, got ${type}`)
        break
      }
      case 'const': if (JSON.stringify(value) !== JSON.stringify(expected)) fail(`expected const ${JSON.stringify(expected)}`); break
      case 'enum': if (!expected.some(item => JSON.stringify(item) === JSON.stringify(value))) fail(`${JSON.stringify(value)} not in enum`); break
      case 'required': if (type === 'object') for (const name of expected) if (!(name in value)) fail(`missing required ${name}`); break
      case 'properties':
        if (type === 'object') for (const [name, child] of Object.entries(expected))
          if (name in value) errors.push(...validate(spec, child, value[name], `${path}.${name}`))
        break
      case 'additionalProperties':
        if (type === 'object') for (const [name, child] of Object.entries(value)) {
          if (schema.properties && name in schema.properties) continue
          if (expected === false) fail(`unexpected property ${name}`)
          else if (typeof expected === 'object') errors.push(...validate(spec, expected, child, `${path}.${name}`))
        }
        break
      case 'propertyNames': if (type === 'object') for (const name of Object.keys(value)) errors.push(...validate(spec, expected, name, `${path}{${name}}`)); break
      case 'maxProperties': if (type === 'object' && Object.keys(value).length > expected) fail(`more than ${expected} properties`); break
      case 'items': if (type === 'array') value.forEach((item, index) => errors.push(...validate(spec, expected, item, `${path}[${index}]`))); break
      case 'minItems': if (type === 'array' && value.length < expected) fail(`fewer than ${expected} items`); break
      case 'maxItems': if (type === 'array' && value.length > expected) fail(`more than ${expected} items`); break
      case 'uniqueItems': if (type === 'array' && expected && new Set(value.map(item => JSON.stringify(item))).size !== value.length) fail('items not unique'); break
      case 'minimum': if (typeof value === 'number' && value < expected) fail(`below minimum ${expected}`); break
      case 'maximum': if (typeof value === 'number' && value > expected) fail(`above maximum ${expected}`); break
      case 'minLength': if (type === 'string' && [...value].length < expected) fail(`shorter than ${expected}`); break
      case 'maxLength': if (type === 'string' && [...value].length > expected) fail(`longer than ${expected}`); break
      case 'pattern': if (type === 'string' && !new RegExp(expected, 'u').test(value)) fail(`does not match ${expected}`); break
      case 'not': if (!validate(spec, expected, value, path).length) fail('matches a forbidden schema'); break
      case 'oneOf': {
        const matches = expected.filter(child => !validate(spec, child, value, path).length).length
        if (matches !== 1) fail(`matches ${matches} oneOf alternatives`)
        break
      }
      case 'anyOf': if (!expected.some(child => !validate(spec, child, value, path).length)) fail('matches no anyOf alternative'); break
      case 'allOf': for (const child of expected) errors.push(...validate(spec, child, value, path)); break
      default: fail(`unsupported schema keyword ${keyword}`)
    }
  }
  return errors
}

/** Returns { file: [errors] } for every fixture; an empty list means the fixture conforms. */
export async function validateFixtures() {
  const spec = JSON.parse(await readFile(new URL('openapi.json', root), 'utf8'))
  const pin = JSON.parse(await readFile(new URL('openapi-version.json', root), 'utf8'))
  const results = {}
  if (spec.info?.version !== pin.version) results['openapi.json'] = [`pinned copy is ${spec.info?.version}, openapi-version.json says ${pin.version}`]
  for (const [file, schema] of Object.entries(fixtures)) {
    const value = JSON.parse(await readFile(new URL(`fixtures/${file}`, root), 'utf8'))
    results[file] = validate(spec, { $ref: `#/components/schemas/${schema}` }, value)
  }
  return results
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const results = await validateFixtures()
  let failed = false
  for (const [file, errors] of Object.entries(results)) {
    console.log(`${errors.length ? 'FAIL' : 'ok  '} ${file}${file in fixtures ? ` (${fixtures[file]})` : ''}`)
    for (const error of errors) console.log(`     ${error}`)
    failed ||= errors.length > 0
  }
  process.exitCode = failed ? 1 : 0
}
