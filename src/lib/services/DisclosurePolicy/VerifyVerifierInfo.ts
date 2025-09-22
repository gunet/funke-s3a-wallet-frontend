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
};

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

		const pem = `-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`;
		const pubKey = await importX509(pem, alg);

		const { payload, protectedHeader } = await jwtVerify(jws, pubKey);

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

		return { ok: true, header: protectedHeader, payload };
	} catch (e: any) {
		return { ok: false, reason: `verification_error:${e?.message ?? String(e)}` };
	}
}
