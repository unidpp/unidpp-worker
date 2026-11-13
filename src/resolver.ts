// The resolution surface on the estate (the adoption audit's gap 1
// closes on the edge): a passport's resolver_uri promises reproducible
// resolution — this surface honors it. The identifier forms the native
// resolver accepts (ISO/IEC 15459 URNs, GS1 element strings, GS1
// Digital Link paths, bare GTINs) resolve against the estate's own
// issuer register into an RFC 9264 linkset whose links name the
// estate's own surfaces (the view, the renderings, the carrier). The
// GS1-conventions path form redirects (303) to the default link; the
// unknown and the dark answer byte-identically (I12).

import type { DoNamespace } from "./views";

export interface ResolverEnv {
  ISSUER?: DoNamespace;
  /** The public origin the links name (default app.unidpp.org). */
  RESOLVER_ORIGIN?: string;
}

const SUPPORTED_AIS: Record<string, string> = { "01": "gtin", "02": "gtin" };

function gtinCheckDigit(gtin13: string): number | null {
  if (!/^\d{13}$/.test(gtin13)) return null;
  let sum = 0;
  for (let i = 0; i < 13; i += 1) {
    const digit = Number(gtin13[i]);
    sum += digit * (i % 2 === 0 ? 3 : 1);
  }
  return (10 - (sum % 10)) % 10;
}

export interface ParsedIdentifier {
  /** The scheme token (gtin | cpid | sgtin | ...) or gtin for the
   *  element-string/DL forms. */
  scheme: string;
  key: string;
  serial?: string;
  lot?: string;
}

/** Parse the identifier forms the native resolver accepts. `dlPath`
 *  carries the GS1 Digital Link path segments (01/..., 21/...). */
export function parseIdentifier(input: string, dlPath?: string[]): ParsedIdentifier | null {
  const text = input.trim();
  if (dlPath && dlPath.length >= 2) {
    // GS1 Digital Link path: /01/<gtin14>[/10/<lot>][/21/<serial>]
    const map: Record<string, string> = {};
    for (let i = 0; i + 1 < dlPath.length; i += 2) {
      map[dlPath[i]] = dlPath[i + 1];
    }
    const ai = Object.keys(map).find((k) => k in SUPPORTED_AIS);
    if (!ai) return null;
    const gtin14 = map[ai];
    if (gtin14.length !== 14) return null;
    const check = gtinCheckDigit(gtin14.slice(0, 13));
    if (check === null || check !== Number(gtin14[13])) return null;
    return {
      scheme: "gtin",
      key: gtin14,
      ...(map["10"] ? { lot: map["10"] } : {}),
      ...(map["21"] ? { serial: map["21"] } : {}),
    };
  }
  // The GS1 element string: 01+<gtin14>[+10+lot][+21+serial]
  if (text.startsWith("01+")) {
    const parts = text.split("+");
    const gtin14 = parts[1] ?? "";
    if (gtin14.length !== 14) return null;
    const check = gtinCheckDigit(gtin14.slice(0, 13));
    if (check === null || check !== Number(gtin14[13])) return null;
    const lot = parts.indexOf("10") >= 0 ? parts[parts.indexOf("10") + 1] : undefined;
    const serial = parts.indexOf("21") >= 0 ? parts[parts.indexOf("21") + 1] : undefined;
    return {
      scheme: "gtin",
      key: gtin14,
      ...(lot ? { lot } : {}),
      ...(serial ? { serial } : {}),
    };
  }
  // A bare 14-digit GTIN (the mod-10 check decides).
  if (/^\d{14}$/.test(text)) {
    const check = gtinCheckDigit(text.slice(0, 13));
    if (check !== null && check === Number(text[13])) {
      return { scheme: "gtin", key: text };
    }
    return null;
  }
  // A scheme-prefixed identifier (cpid:..., sgtin:..., local:...):
  // accept the forms the model parses; the key rides after the colon.
  const colon = text.indexOf(":");
  if (colon > 0) {
    const scheme = text.slice(0, colon);
    const rest = text.slice(colon + 1);
    if (["cpid", "sgtin", "gsrn", "gln", "ssn", "upu", "vin", "handle", "doi", "uri"].includes(scheme)) {
      return { scheme, key: rest };
    }
    if (scheme === "urn" && text.includes(":unidpp:passport:")) {
      // The ISO/IEC 15459 URN form names the passport itself.
      return { scheme: "passport", key: text };
    }
    return null;
  }
  return null;
}

/** The estate's passports, each with its document's subject. */
async function estatePassports(
  env: ResolverEnv,
): Promise<{ passportId: string; subject: string }[]> {
  if (!env.ISSUER) return [];
  const stub = env.ISSUER.get(env.ISSUER.idFromName("estate"));
  const response = await stub.fetch(new Request("https://do.internal/passports"));
  if (response.status !== 200) return [];
  const listed = (await response.json()) as {
    passports?: { passport_id: string; subject?: string }[];
  };
  return (listed.passports ?? []).map((p) => ({
    passportId: p.passport_id,
    subject: p.subject ?? "",
  }));
}

function matchSubject(subject: string, ident: ParsedIdentifier): boolean {
  // The GS1 family prints as the element string `01+<key>`; the rest
  // as `scheme:key`.
  if (ident.scheme === "gtin") {
    return subject === `01+${ident.key}`;
  }
  if (ident.scheme === "passport") {
    return false; // the passport id matches below, not the subject
  }
  return subject === `${ident.scheme}:${ident.key}`;
}

function linksetDocument(
  ident: ParsedIdentifier,
  passportId: string,
  origin: string,
): Record<string, unknown> {
  // The anchor IS the passport's URN; the estate's minted passports
  // already carry the urn: scheme, so never prefix twice.
  const anchor = passportId.startsWith("urn:") ? passportId : `urn:unidpp:passport:${passportId}`;
  const link = (href: string, rel: string, type: string, title: string) => ({
    href,
    rel,
    type,
    title,
  });
  return {
    linkset: [
      {
        anchor,
        link: [
          link(`${origin}/views/view?passport=${encodeURIComponent(passportId)}`, "dpp", "application/json", "The lens view"),
          link(`${origin}/render/untp/product/${encodeURIComponent(passportId)}`, "dpp-rendering", "application/json", "The UNTP rendering"),
          link(
            `${origin}/render/en18222/v1/dppsByProductId/${encodeURIComponent(
              ident.scheme === "gtin" ? ident.key : passportId,
            )}`,
            "dpp-rendering",
            "application/json",
            "The EN 18222 rendering",
          ),
        ],
      },
    ],
  };
}

export async function resolveQuery(request: Request, env: ResolverEnv): Promise<Response> {
  const params = new URL(request.url).searchParams;
  const identifier = params.get("identifier");
  const carrier = params.get("carrier");
  if (identifier && carrier) {
    return jsonResponse({ error: "`carrier` and `identifier` are mutually exclusive" }, 400);
  }
  let input: string | null = null;
  let dlPath: string[] | undefined;
  if (identifier) input = identifier;
  if (carrier) {
    // The carrier form: a GS1 Digital Link URL or an element string —
    // the native resolver translates, then resolves.
    try {
      const url = new URL(carrier);
      dlPath = url.pathname.split("/").filter(Boolean); // /01/<gtin14>/...
      input = "";
    } catch {
      input = carrier;
    }
  }
  if (input === null) {
    return jsonResponse({ error: "one of `carrier` or `identifier` is required" }, 400);
  }
  const ident = parseIdentifier(input, dlPath);
  if (!ident) {
    return jsonResponse({ error: `unparseable identifier \`${input}\`` }, 400);
  }
  const origin = env.RESOLVER_ORIGIN ?? "https://app.unidpp.org";
  const passports = await estatePassports(env);
  // The passport form matches the passport id itself.
  if (ident.scheme === "passport") {
    const passportId = ident.key;
    const found = passports.some((p) => p.passportId === passportId);
    if (!found) return jsonResponse({}, 404);
    return jsonResponse(linksetDocument({ scheme: "cpid", key: passportId }, passportId, origin));
  }
  for (const entry of passports) {
    if (matchSubject(entry.subject, ident)) {
      return jsonResponse(linksetDocument(ident, entry.passportId, origin));
    }
  }
  // The no-information 404: unknown and dark answer identically (I12).
  return jsonResponse({}, 404);
}

/** The GS1-conventions path form: `/{01}/{gtin}/...` → 303 to the
 *  default link; `.../linkset` → the document. */
export async function resolvePath(
  segments: string[],
  request: Request,
  env: ResolverEnv,
): Promise<Response> {
  const wantLinkset = segments[segments.length - 1] === "linkset";
  const keyPath = wantLinkset ? segments.slice(0, -1) : segments;
  const ident = parseIdentifier("", keyPath);
  if (!ident) return jsonResponse({}, 404);
  const origin = env.RESOLVER_ORIGIN ?? "https://app.unidpp.org";
  const passports = await estatePassports(env);
  for (const entry of passports) {
    if (matchSubject(entry.subject, ident)) {
      const defaultHref = `${origin}/views/view?passport=${encodeURIComponent(entry.passportId)}`;
      if (wantLinkset) {
        return jsonResponse(linksetDocument(ident, entry.passportId, origin), 200, "application/linkset+json");
      }
      return new Response("", { status: 303, headers: { location: defaultHref } });
    }
  }
  return jsonResponse({}, 404);
}

const jsonResponse = (
  body: unknown,
  status = 200,
  contentType = "application/json",
): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": contentType },
  });
