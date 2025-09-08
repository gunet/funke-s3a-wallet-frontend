import { z } from "zod";

export const TransactionDataRequestObject = z.object({
	type: z.literal('urn:wwwallet:example_transaction_data_type'),
	credential_ids: z.array(z.string()),
}).or(z.object({
	type: z.literal('qes_authorization'),
	credential_ids: z.array(z.string()),
	signatureQualifier: z.string(),
	transaction_data_hashes_alg: z.array(z.enum(["sha-256"])),
	documentDigests: z.array(z.object({
		hash: z.string().optional(),
		label: z.string(),
		hashAlgorithmOID: z.string(),
	}))
})).or(z.object({
	type: z.literal('qcert_creation_acceptance'),
	credential_ids: z.array(z.string()),
	QC_terms_conditions_uri: z.string().optional(),
	QC_hash: z.string().optional(),
	QC_hashAlgorithmOID: z.string().optional(),
	transaction_data_hashes_alg: z.array(z.enum(["sha-256"])),
}));

export type TransactionDataRequest = z.infer<typeof TransactionDataRequestObject>;
