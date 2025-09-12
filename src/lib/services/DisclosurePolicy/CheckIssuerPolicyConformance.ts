import { verifyVerifierInfo } from "./VerifyVerifierInfo";

type ConformantMap = Record<
  string, // descriptorId
  { credentials: number[] }
>;

type VCEntity = {
  batchId: number;
  parsedCredential?: {
    metadata?: {
      credential?: {
        disclosurePolicy?: object | null
      };
    };
  };
};

export type PolicyViolation = {
  descriptorId: string;
  message: string;
};

/**
 * Check issuer policy conformance for each requested descriptor.
 * If every conformant credential for a descriptor requires 'attestationBased',
 * then a valid verifierInfoSdJwt must be present; otherwise violation.
 */

export async function checkIssuerPolicyConformance(
  options: {
    conformantCredentialsMap: ConformantMap;
    vcEntityList: VCEntity[];
    verifierInfoArr: Array<{ format: string, data: string }>;
		parseCredential: Function;
  }
): Promise<PolicyViolation[]> {
  const { conformantCredentialsMap, vcEntityList, verifierInfoArr, parseCredential } = options;
  const violations: PolicyViolation[] = [];

  async function isAnyVerifierInfoValid() {
		const result = await verifyVerifierInfo(verifierInfoArr, parseCredential);
    return result.ok;
  }

  const requiresAttestation = (policyObject: object): boolean => {
    if (policyObject && typeof policyObject === "object") {
      return policyObject['policy'] === "attestationBased";
    }
    return false;
  };

  async function check() {
    for (const [descriptorId, entry] of Object.entries(conformantCredentialsMap || {})) {
      const candidateEntities = vcEntityList.filter((vc) => entry.credentials.includes(vc.batchId));
      if (candidateEntities.length === 0) continue;

      const candidateRequires = candidateEntities.map((vc) =>
        requiresAttestation(vc?.parsedCredential?.metadata?.credential?.disclosurePolicy)
      );

      const allRequireAttestation = candidateRequires.length > 0 && candidateRequires.every(Boolean);

      // If all candidates require attestation-based disclosure, the verifier should provide a valid verifier_info
      if (allRequireAttestation) {
        const valid = await isAnyVerifierInfoValid();
        if (!valid) {
          violations.push({
            descriptorId,
            message:
              "Issuer policy requires attestation-based disclosure, but no valid verifier attestation (verifier_info) was provided."
          });
        }
      }
    }
    return violations;
	}
	return await check();
}
