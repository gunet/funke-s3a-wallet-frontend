// import { importX509, jwtVerify } from "jose";
import { VerifiableCredentialFormat } from "wallet-common/dist/types";

/**
 * Verifies an array of verifier_info objects (dc+sd-jwt).
 * Returns { ok, payload, format } for the first valid one or an error.
 */
export async function verifyVerifierInfo(
  verifierInfoArr: Array<{ format: string, data: string, credential_ids?: string[] }>,
	parseCredential?: Function
): Promise<
  { ok: true; payload: any; format: string } | { ok: false; reason: string }
> {
  if (!verifierInfoArr || verifierInfoArr.length === 0) return { ok: false, reason: "missing" };

  for (const viObj of verifierInfoArr) {
    try {
      // if (viObj.format === "jwt") {
      //   const [encodedHeader] = viObj.data.split(".");
      //   const header = JSON.parse(new TextDecoder().decode(base64urlToUint8(encodedHeader)));
      //   if (!header?.x5c?.[0]) continue;
      //   const pem = `-----BEGIN CERTIFICATE-----\n${header.x5c[0]}\n-----END CERTIFICATE-----`;
      //   const publicKey = await importX509(pem, header.alg || "ES256");
      //   const { payload } = await jwtVerify(viObj.data, publicKey);
      //   if (payload?.exp && payload.exp * 1000 < Date.now()) continue;
      //   return { ok: true, payload, format: "jwt" };
      // } 
			if (viObj.format === VerifiableCredentialFormat.DC_SDJWT) {
				const result = await parseCredential(viObj);
				console.log("verifyVerifierInfo: parseCredential result = ", result);
				const {  validUntil } = result.validityInfo;
				if (Math.floor(validUntil.getTime() / 1000) < Math.floor(new Date().getTime() / 1000)){
					continue;
				};
				return { ok: true, payload: result.signedClaims, format: "dc+sd-jwt" };
      }
    } catch (e) {
      console.warn("Error verifying verifier_info:", e);
    }
  }
  return { ok: false, reason: "no_valid_verifier_info" };
}

// function base64urlToUint8(b64u: string): Uint8Array {
//   const pad = (s: string) => s + "===".slice((s.length + 3) % 4);
//   const b64 = pad(b64u.replace(/-/g, "+").replace(/_/g, "/"));
//   const bin = atob(b64);
//   const bytes = new Uint8Array(bin.length);
//   for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
//   return bytes;
// }
