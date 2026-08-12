/**
 * Canonical JSON, byte-identical to the recorder's.
 *
 * Both sides hash and sign the same structures, so a difference here is a
 * silent interoperability break: signatures would verify on one side and not
 * the other, and the failure would look like tampering. Built with
 * Object.create(null) for the reason the recorder's security review found —
 * assigning "__proto__" into an object literal hits the prototype setter and
 * the key vanishes from the output, letting two different values hash alike.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const src = value as Record<string, unknown>;
    const out = Object.create(null) as Record<string, unknown>;
    for (const k of Object.keys(src).sort()) out[k] = sortKeys(src[k]);
    return out;
  }
  return value;
}
