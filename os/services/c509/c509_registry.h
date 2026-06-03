/**
 * @file c509_registry.h
 * @brief C509 IANA Registry constants — draft-ietf-cose-cbor-encoded-cert-19
 *
 * Integer IDs are from the IANA registries defined in Section 9 of the draft.
 * Negative extension IDs signal critical extensions on the wire; the absolute
 * value is the registry ID.  Use C509_EXT_IS_CRITICAL(wire_id) to test.
 */

#ifndef C509_REGISTRY_H
#define C509_REGISTRY_H

/* ── Signature Algorithm IDs (Section 9.1, Table 3) ────────────────────── */
/* Legacy / negative range */
#define C509_SIG_RSA_V15_SHA1              -256
#define C509_SIG_ECDSA_SHA1                -255
/* Standard positive range */
#define C509_SIG_ECDSA_SHA256              0
#define C509_SIG_ECDSA_SHA384              1
#define C509_SIG_ECDSA_SHA512              2
#define C509_SIG_ECDSA_SHAKE128            3
#define C509_SIG_ECDSA_SHAKE256            4
#define C509_SIG_SM2_SM3                   8
#define C509_SIG_ED25519                   12
#define C509_SIG_ED448                     13
#define C509_SIG_ECDHPOP_SHA256            14
#define C509_SIG_ECDHPOP_SHA384            15
#define C509_SIG_ECDHPOP_SHA512            16
#define C509_SIG_RSA_V15_SHA256            23
#define C509_SIG_RSA_V15_SHA384            24
#define C509_SIG_RSA_V15_SHA512            25
#define C509_SIG_RSA_PSS_SHA256            26
#define C509_SIG_RSA_PSS_SHA384            27
#define C509_SIG_RSA_PSS_SHA512            28
#define C509_SIG_RSA_PSS_SHAKE128          29
#define C509_SIG_RSA_PSS_SHAKE256          30

/* ── Public Key Algorithm IDs (Section 9.2, Table 4) ───────────────────── */
#define C509_PK_RSA                        0
#define C509_PK_SECP256R1                  1
#define C509_PK_SECP384R1                  2
#define C509_PK_SECP521R1                  3
#define C509_PK_SM2P256V1                  6
#define C509_PK_X25519                     8
#define C509_PK_X448                       9
#define C509_PK_ED25519                    12
#define C509_PK_ED448                      13
#define C509_PK_BRAINPOOLP256R1            24
#define C509_PK_BRAINPOOLP384R1            25
#define C509_PK_BRAINPOOLP512R1            26
#define C509_PK_FRP256V1                   27

/* ── RDN Attribute IDs (Section 9.3, Table 5) ──────────────────────────── */
#define C509_ATT_EMAIL                     0
#define C509_ATT_COMMON_NAME               1
#define C509_ATT_SUR_NAME                  2
#define C509_ATT_SERIAL_NUMBER             3
#define C509_ATT_COUNTRY                   4
#define C509_ATT_LOCALITY                  5
#define C509_ATT_STATE_OR_PROVINCE         6
#define C509_ATT_STREET_ADDRESS            7
#define C509_ATT_ORGANIZATION              8
#define C509_ATT_ORGANIZATION_UNIT         9
#define C509_ATT_TITLE                     10
#define C509_ATT_BUSINESS_CATEGORY         11
#define C509_ATT_POSTAL_CODE               12
#define C509_ATT_GIVEN_NAME                13
#define C509_ATT_INITIALS                  14
#define C509_ATT_GENERATION_QUALIFIER      15
#define C509_ATT_DN_QUALIFIER              16
#define C509_ATT_PSEUDONYM                 17
#define C509_ATT_ORGANIZATION_IDENTIFIER   18
#define C509_ATT_JURISDICTION_LOCALITY     19
#define C509_ATT_JURISDICTION_STATE        20
#define C509_ATT_JURISDICTION_COUNTRY      21
#define C509_ATT_DOMAIN_COMPONENT          22
#define C509_ATT_NAME                      25
#define C509_ATT_TELEPHONE_NUMBER          26
#define C509_ATT_DIR_MAN_DOMAIN_NAME       27
#define C509_ATT_USER_ID                   28
#define C509_ATT_UNSTRUCTURED_NAME         29
#define C509_ATT_UNSTRUCTURED_ADDRESS      30

/* ── Extension IDs (Section 9.4, Table 6) ──────────────────────────────── */
/* On the wire: critical extensions have their ID encoded as a negative CBOR
 * integer (-id).  Non-critical use a positive integer (id).
 * Note: SCT List (old ID 10) was removed from the registry in draft-11. */
#define C509_EXT_SUBJECT_KEY_ID            1
#define C509_EXT_KEY_USAGE                 2
#define C509_EXT_SUBJECT_ALT_NAME          3
#define C509_EXT_BASIC_CONSTRAINTS         4
#define C509_EXT_CRL_DIST_POINTS           5
#define C509_EXT_CERT_POLICIES             6
#define C509_EXT_AUTHORITY_KEY_ID          7
#define C509_EXT_EXT_KEY_USAGE             8
#define C509_EXT_AUTHORITY_INFO_ACCESS     9
#define C509_EXT_SUBJECT_DIRECTORY_ATTR    24
#define C509_EXT_ISSUER_ALT_NAME           25
#define C509_EXT_NAME_CONSTRAINTS          26
#define C509_EXT_POLICY_MAPPINGS           27
#define C509_EXT_POLICY_CONSTRAINTS        28
#define C509_EXT_FRESHEST_CRL              29
#define C509_EXT_INHIBIT_ANY_POLICY        30
#define C509_EXT_SUBJECT_INFO_ACCESS       31
#define C509_EXT_IP_ADDR_BLOCKS            32
#define C509_EXT_AS_IDENTIFIERS            33
#define C509_EXT_IP_ADDR_BLOCKS_V2         34
#define C509_EXT_AS_IDENTIFIERS_V2         35
#define C509_EXT_OCSP_NO_CHECK             36
#define C509_EXT_TLS_FEATURES              38

/* Decode wire ID → registry ID and criticality.
 * C509 encodes critical extension IDs as CBOR NINT: wire = -(id) - 1.
 * For a decoded CBOR value: if type==NINT, id = -(val+1); if UINT, id = val. */
#define C509_EXT_IS_CRITICAL(wire_id)   ((wire_id) < 0)
#define C509_EXT_ABS_ID(wire_id)        ((wire_id) < 0 ? -(wire_id) : (wire_id))

/* ── Extended Key Usage IDs (Section 9.8) ───────────────────────────────── */
#define C509_EKU_TLS_SERVER                1
#define C509_EKU_TLS_CLIENT                2
#define C509_EKU_CODE_SIGNING              3
#define C509_EKU_EMAIL_PROTECTION          4
#define C509_EKU_TIME_STAMPING             8
#define C509_EKU_OCSP_SIGNING              9

#endif /* C509_REGISTRY_H */
