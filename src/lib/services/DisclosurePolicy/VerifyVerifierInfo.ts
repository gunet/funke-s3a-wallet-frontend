import { importX509, jwtVerify, decodeProtectedHeader } from "jose";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";

function issuerJwsFromSdJwt(sdjwt: string): string {
	const i = sdjwt.indexOf("~");
	return i === -1 ? sdjwt : sdjwt.slice(0, i);
}

export type VerifierInfoEntry = {
	format: VerifiableCredentialFormat.DC_SDJWT | VerifiableCredentialFormat.VC_SDJWT;
	data: string;
	credential_ids?: string[];
};

export type VerifyOpts = {
	expectedVct?: string;
	expectedFormat?: string;
	expectTypContains?: string;
	allowedAuthorityKeyIdsHex?: string[];
};

const normHex = (s: string) => s.toLowerCase().replace(/[^0-9a-f]/g, "");
const wrapPem = (b64: string) =>
	`-----BEGIN CERTIFICATE-----\n${(b64.match(/.{1,64}/g) ?? [b64]).join("\n")}\n-----END CERTIFICATE-----`;
const b64ToBytes = (b64: string) =>
	Uint8Array.from(atob(b64), c => c.charCodeAt(0));

/** Basic DER TLV reader */
function readLen(buf: Uint8Array, o: number) {
	let len = buf[o++];
	if (len < 0x80) return { len, o };
	const n = len & 0x7f;
	let v = 0;
	for (let i = 0; i < n; i++) v = (v << 8) | buf[o++];
	return { len: v, o };
}
function tlv(buf: Uint8Array, o: number) {
	const tag = buf[o++];
	const { len, o: o2 } = readLen(buf, o);
	const vStart = o2;
	const vEnd = o2 + len;
	return { tag, vStart, vEnd, next: vEnd };
}

/** Extract SPKI (SubjectPublicKeyInfo) VALUE bytes from a DER X.509 cert */
function spkiFromCertDer(der: Uint8Array): Uint8Array {
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	let o = 0;
	const certSeq = tlv(der, o);
	if (certSeq.tag !== 0x30) throw new Error("bad cert");
	o = certSeq.vStart;

	// tbsCertificate
	const tbs = tlv(der, o);
	if (tbs.tag !== 0x30) throw new Error("bad tbs");
	o = tbs.vStart;

	// [0] EXPLICIT version (optional)
	if (der[o] === 0xa0) o = tlv(der, o).next;

	// serialNumber (INTEGER)
	if (der[o] !== 0x02) throw new Error("bad serial");
	o = tlv(der, o).next;

	// signature (SEQUENCE)
	if (der[o] !== 0x30) throw new Error("bad sig alg");
	o = tlv(der, o).next;

	// issuer (SEQUENCE)
	if (der[o] !== 0x30) throw new Error("bad issuer");
	o = tlv(der, o).next;

	// validity (SEQUENCE)
	if (der[o] !== 0x30) throw new Error("bad validity");
	o = tlv(der, o).next;

	// subject (SEQUENCE)
	if (der[o] !== 0x30) throw new Error("bad subject");
	o = tlv(der, o).next;

	// subjectPublicKeyInfo (SEQUENCE) — return its VALUE bytes
	const spki = tlv(der, o);
	if (spki.tag !== 0x30) throw new Error("bad spki");
	return der.subarray(spki.vStart, spki.vEnd);
}

/** From SPKI VALUE, get BIT STRING subjectPublicKey (skip 1 unused-bits byte) */
function subjectPublicKeyFromSpki(spkiVal: Uint8Array): Uint8Array {
	let o = 0;
	// AlgorithmIdentifier (SEQUENCE) — skip
	if (spkiVal[o] !== 0x30) throw new Error("bad algid");
	o = tlv(spkiVal, o).next;

	// subjectPublicKey (BIT STRING)
	if (spkiVal[o] !== 0x03) throw new Error("bad subjectPublicKey bitstring");
	const bit = tlv(spkiVal, o);
	const unused = spkiVal[bit.vStart]; // usually 0
	if (unused > 7) throw new Error("bad unused bits");
	return spkiVal.subarray(bit.vStart + 1, bit.vEnd);
}

/** SKI hex = SHA-1(subjectPublicKey) */
async function computeLeafSkiHexFromX5cB64(certB64: string): Promise<string> {
	const der = b64ToBytes(certB64);
	const spkiVal = spkiFromCertDer(der);
	const spk = subjectPublicKeyFromSpki(spkiVal);
	const digest = await crypto.subtle.digest("SHA-1", spk);
	return Array.from(new Uint8Array(digest))
		.map(b => b.toString(16).padStart(2, "0"))
		.join("");
}

/** Return the tbsCertificate VALUE slice and the offset right after it. */
function tbsFromCertDer(der: Uint8Array) {
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	let o = 0;
	const certSeq = tlv(der, o);
	if (certSeq.tag !== 0x30) throw new Error("bad cert");
	o = certSeq.vStart;

	const tbs = tlv(der, o);
	if (tbs.tag !== 0x30) throw new Error("bad tbs");
	return { tbsVal: der.subarray(tbs.vStart, tbs.vEnd) };
}

/** Find Extensions ([3] EXPLICIT) inside tbsCertificate and return the SEQUENCE VALUE of extensions. */
function extensionsSeqFromTbs(tbs: Uint8Array): Uint8Array | null {
	let o = 0;

	// OPTIONAL version [0] EXPLICIT
	if (tbs[o] === 0xa0) o = tlv(tbs, o).next;

	// serialNumber (INTEGER)
	if (tbs[o] !== 0x02) throw new Error("bad serial");
	o = tlv(tbs, o).next;

	// signature (SEQUENCE)
	if (tbs[o] !== 0x30) throw new Error("bad sig alg");
	o = tlv(tbs, o).next;

	// issuer (SEQUENCE)
	if (tbs[o] !== 0x30) throw new Error("bad issuer");
	o = tlv(tbs, o).next;

	// validity (SEQUENCE)
	if (tbs[o] !== 0x30) throw new Error("bad validity");
	o = tlv(tbs, o).next;

	// subject (SEQUENCE)
	if (tbs[o] !== 0x30) throw new Error("bad subject");
	o = tlv(tbs, o).next;

	// subjectPublicKeyInfo (SEQUENCE)
	if (tbs[o] !== 0x30) throw new Error("bad spki");
	o = tlv(tbs, o).next;

	// OPTIONAL issuerUniqueID [1], subjectUniqueID [2]
	while (tbs[o] === 0xa1 || tbs[o] === 0xa2) o = tlv(tbs, o).next;

	// extensions [3] EXPLICIT
	if (tbs[o] !== 0xa3) return null; // no extensions
	const extCtx = tlv(tbs, o);
	const seq = tlv(tbs.subarray(extCtx.vStart, extCtx.vEnd), 0);
	if (seq.tag !== 0x30) throw new Error("bad extensions seq");
	return tbs.subarray(extCtx.vStart + (seq.vStart - 0), extCtx.vStart + (seq.vEnd - 0));
}

/** Extract Authority Key Identifier (keyIdentifier) from the leaf cert. Returns lowercase hex. */
function extractLeafAkiKeyIdHexFromX5cB64(certB64: string): string | null {
	const der = b64ToBytes(certB64);
	const { tbsVal } = tbsFromCertDer(der);
	const extSeq = extensionsSeqFromTbs(tbsVal);
	if (!extSeq) return null;

	// Iterate Extension ::= SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
	let o = 0;
	while (o < extSeq.length) {
		const ext = tlv(extSeq, o);
		if (ext.tag !== 0x30) throw new Error("bad extension");
		const extVal = extSeq.subarray(ext.vStart, ext.vEnd);
		o = ext.next;

		let eo = 0;
		const oidTlv = tlv(extVal, eo); eo = oidTlv.next;
		if (oidTlv.tag !== 0x06) throw new Error("bad ext oid");

		// OID 2.5.29.35 -> DER bytes 06 03 55 1D 23 (we compare value only)
		const oidVal = extVal.subarray(oidTlv.vStart, oidTlv.vEnd);
		const isAKI =
			oidVal.length === 3 &&
			oidVal[0] === 0x55 && oidVal[1] === 0x1D && oidVal[2] === 0x23;

		// optional critical
		let nextTag = extVal[eo];
		if (nextTag === 0x01) eo = tlv(extVal, eo).next;

		// extnValue OCTET STRING
		if (extVal[eo] !== 0x04) throw new Error("bad extnValue");
		const extn = tlv(extVal, eo);
		eo = extn.next;

		if (!isAKI) continue;

		// extn.value is DER of AuthorityKeyIdentifier ::= SEQUENCE { [0] keyIdentifier OCTET STRING, ... }
		const v = extVal.subarray(extn.vStart, extn.vEnd);
		const inner = tlv(v, 0); // should be SEQUENCE
		if (inner.tag !== 0x30) throw new Error("bad AKI seq");
		let io = inner.vStart;

		// Look for context-specific [0] (0x80) — keyIdentifier (IMPLICIT OCTET STRING)
		if (v[io] !== 0x80) return null; // keyIdentifier missing
		const kidTlv = tlv(v, io);
		const kid = v.subarray(kidTlv.vStart, kidTlv.vEnd);
		return Array.from(kid).map(b => b.toString(16).padStart(2, "0")).join("");
	}

	return null;
}


export async function verifyVerifierInfoData(
	entry: VerifierInfoEntry,
	opts: VerifyOpts = {}
): Promise<{ ok: true; header: any; payload: any } | { ok: false; reason: string }> {
	try {
		const jws = entry.format === VerifiableCredentialFormat.DC_SDJWT
			? issuerJwsFromSdJwt(entry.data)
			: entry.data;
		const header = decodeProtectedHeader(jws);

		// ---- sig verification ----
		const x5c: string[] | undefined = Array.isArray(header?.x5c) ? header.x5c : undefined;
		const alg: string | undefined = typeof header?.alg === "string" ? header.alg : undefined;
		if (!x5c || x5c.length === 0 || !alg) {
			return { ok: false, reason: "missing_x5c_or_alg" };
		}

		const pubKey = await importX509(wrapPem(x5c[0]), alg);
		const { payload, protectedHeader } = await jwtVerify(jws, pubKey);

		if (payload.exp && payload.exp * 1000 < Date.now()) {
			return { ok:false, reason:"attestation_expired" };
		}
		// ---- policy checks ----
		if (opts.expectedFormat && opts.expectedFormat !== entry.format) {
			console.log(`Format mismatch: expected ${opts.expectedFormat}, got ${entry.format}`);
			return { ok: false, reason: `format_mismatch:${entry.format}!=${opts.expectedFormat}` };
		}

		if (opts.expectTypContains && protectedHeader?.typ && String(protectedHeader.typ) !== opts.expectTypContains) {
			console.log(`Typ mismatch: expected to contain ${opts.expectTypContains}, got ${protectedHeader.typ}`);
			return { ok: false, reason: `typ_mismatch:${protectedHeader.typ}` };
		}
		if (opts.expectedVct && (payload as any)?.vct !== opts.expectedVct) {
			console.log(`VCT mismatch: expected ${opts.expectedVct}, got ${(payload as any)?.vct}`);
			return { ok: false, reason: `vct_mismatch:${(payload as any)?.vct}` };
		}

		// ---- AKI authority enforcement ----
		if (opts.allowedAuthorityKeyIdsHex && opts.allowedAuthorityKeyIdsHex.length > 0) {
			const allowed = new Set(opts.allowedAuthorityKeyIdsHex.map(normHex));
			const leafSki = await extractLeafAkiKeyIdHexFromX5cB64(x5c[0]);
			if (!allowed.has(leafSki)) {
				return { ok: false, reason: "authority_not_trusted" };
			}
		}

		return { ok: true, header: protectedHeader, payload };
	} catch (e: any) {
		return { ok: false, reason: `verification_error:${e?.message ?? String(e)}` };
	}
}
