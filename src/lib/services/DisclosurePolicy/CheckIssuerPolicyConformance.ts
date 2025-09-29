import { VerifiableCredentialFormat } from "wallet-common/dist/types";
import { verifyVerifierInfoData, VerifierInfoEntry, VerifyOpts } from "./VerifyVerifierInfo";

type ConformantMap = Record<
	string, // descriptorId
	{
		credentials: number[];
		requestedFields?: any[];
	}
>;

type VCEntity = {
	batchId: number;
	parsedCredential?: {
		metadata?: {
			credential?: {
				vct?: string;
				disclosurePolicy?: {
					policy?: "attestationBased" | string;
					url?: string;
					values?: Array<{
						credentials: Array<{
							id: string;
							format:
								| VerifiableCredentialFormat.DC_SDJWT
								| VerifiableCredentialFormat.VC_SDJWT;
							meta?: {
								vct_values?: string[]; // e.g. ["urn:eudi:authorization_attestation"]
							};
						}>;
					}>;
				} | null;
			};
		};
	};
};

export type PolicyViolation = {
	descriptorId: string;
	message: string;
};

type Options = {
	conformantCredentialsMap: ConformantMap;
	vcEntityList: VCEntity[];
	verifierInfoArr: VerifierInfoEntry[];
	expectedTypForDcSdJwt?: string; // e.g. "dc+sd-jwt"
};

export async function checkIssuerPolicyConformance(opts: Options): Promise<PolicyViolation[]> {
	const {
		conformantCredentialsMap,
		vcEntityList,
		verifierInfoArr,
		expectedTypForDcSdJwt = VerifiableCredentialFormat.DC_SDJWT,
	} = opts;

	const violations: PolicyViolation[] = [];

	const requiresAttestation = (
		policy?: VCEntity["parsedCredential"]["metadata"]["credential"]["disclosurePolicy"]
	) => policy && policy.policy === "attestationBased";

	// Try to find an acceptable verifier_info for a single issuer policy credential requirement
	async function hasAcceptableVerifierInfo(policyCred: {
		id: string;
		format: VerifiableCredentialFormat.DC_SDJWT | VerifiableCredentialFormat.VC_SDJWT;
		meta?: { vct_values?: string[] };
	}): Promise<boolean> {
		for (const vi of verifierInfoArr || []) {
			// if verifier_info has credential_ids, it must include the issuer policy credential id
			if (Array.isArray(vi.credential_ids) && vi.credential_ids.length > 0) {
				if (!vi.credential_ids.includes(policyCred.id)) continue;
			}

			const ta = (policyCred as any)?.trusted_authorities;
			const allowedAKIs = (ta?.type === "aki" && Array.isArray(ta.values)) ? ta.values : undefined;


			const baseVerifyOpts: VerifyOpts = {
				expectedFormat: policyCred.format,
				expectTypContains:
					policyCred.format === VerifiableCredentialFormat.DC_SDJWT
						? expectedTypForDcSdJwt
						: undefined,
					allowedAuthorityKeyIdsHex: allowedAKIs,
			};

			// if issuer declared acceptable VCTs, accept any that matchesm, otherwise skip VCT check
			const vctValues =
				policyCred.meta?.vct_values && policyCred.meta.vct_values.length > 0
					? policyCred.meta.vct_values
					: [undefined];

			for (const vct of vctValues) {
				const verifyOpts = vct ? { ...baseVerifyOpts, expectedVct: vct } : baseVerifyOpts;
				const res = await verifyVerifierInfoData(vi, verifyOpts);
				if (res.ok) return true;
			}
		}
		return false;
	}

	for (const [descriptorId, entry] of Object.entries(conformantCredentialsMap || {})) {
		// all conforming credentials in the wallet for this descriptor
		const candidateEntities = vcEntityList.filter(vc => entry.credentials.includes(vc.batchId));
		if (candidateEntities.length === 0) continue;

		// check if every matching credential is governed by an attestationBased policy
		const allRequire = candidateEntities.every(vc =>
			requiresAttestation(vc?.parsedCredential?.metadata?.credential?.disclosurePolicy)
		);
		if (!allRequire) continue;

		// Collect issuer policy blocks from those credentials
		const policies = candidateEntities
			.map(vc => vc?.parsedCredential?.metadata?.credential?.disclosurePolicy)
			.filter(Boolean);

		const requiredAttestations =
			policies.flatMap(p => p!.values || [])
							.flatMap(v => v.credentials || []);

		// Issuer requires attestationBased but didn’t specify any attestation credential
		if (requiredAttestations.length === 0) {
			violations.push({
				descriptorId,
				message:
					"Issuer policy requires attestation-based disclosure, but no specific attestation credentials were declared by the issuer.",
			});
			continue;
		}

		// Accept if any declared policy credential can be satisfied by a valid verifier_info
		let ok = false;
		for (const policyCred of requiredAttestations) {
			if (await hasAcceptableVerifierInfo(policyCred)) {
				ok = true;
				break;
			}
		}

		if (!ok) {
			violations.push({
				descriptorId,
				message:
					"The verifier's request did not satisfy the issuer’s disclosure policy for this credential.",
			});
		}
	}

	return violations;
}
