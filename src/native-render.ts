// The native estate's JSON rendering: recursively sorted keys with a
// two-space indent — the form the native services' serde writer
// produces. The estate's Durable Objects answer in the same form, so
// an adopter diffing the deployments sees the same bytes. The
// boundary-call serializations stay compact (the wasm parses either).

export const sortedValue = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, sortedValue(v)]),
    );
  }
  return value;
};

export const renderNative = (body: unknown): string =>
  JSON.stringify(sortedValue(body), null, 2);
