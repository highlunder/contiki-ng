/**
 * @file x509_encode.c
 * @brief Implementation of X.509 DER encoding for C509 components.
 */

#include "x509_encode.h"
#include "der.h"
#include <string.h>
#include <stdio.h>

// OIDs
static const uint8_t OID_ECDSA_SHA256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const uint8_t OID_EC_PUBKEY[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t OID_SECP256R1[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OID_COMMON_NAME[] = { 0x55, 0x04, 0x03 };

// Extension OIDs
static const uint8_t OID_SKI[] = { 0x55, 0x1D, 0x0E };
static const uint8_t OID_KEY_USAGE[] = { 0x55, 0x1D, 0x0F };
static const uint8_t OID_BASIC_CONSTRAINTS[] = { 0x55, 0x1D, 0x13 };
static const uint8_t OID_EKU[] = { 0x55, 0x1D, 0x25 };
static const uint8_t OID_SERVER_AUTH[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };

/* Helper to write a tag, length, and content */
static int write_tag_content(uint8_t *buffer, size_t size, size_t *offset, uint8_t tag, const uint8_t *content, size_t content_len) {
    if (der_write_tag_len(buffer, size, offset, tag, content_len) != 0) return -1;
    if (*offset + content_len > size) return -1;
    if (content_len > 0 && content != NULL) {
        memcpy(buffer + *offset, content, content_len);
        *offset += content_len;
    }
    return 0;
}

static int encode_alg_id(uint8_t *buffer, size_t size, size_t *offset, int64_t alg_id) {
    uint8_t content[64]; size_t c_off = 0;
    const uint8_t *oid; size_t oid_len;
    int include_params = 0;
    const uint8_t *params = NULL; size_t params_len = 0;

    if (alg_id == 0 || alg_id == 8) {
        oid = OID_ECDSA_SHA256; oid_len = sizeof(OID_ECDSA_SHA256);
    } else if (alg_id == 1) {
        oid = OID_EC_PUBKEY; oid_len = sizeof(OID_EC_PUBKEY);
        params = OID_SECP256R1; params_len = sizeof(OID_SECP256R1);
        include_params = 1;
    } else return -1;

    if (write_tag_content(content, sizeof(content), &c_off, DER_TAG_OID, oid, oid_len) != 0) return -1;
    if (include_params) {
        if (write_tag_content(content, sizeof(content), &c_off, DER_TAG_OID, params, params_len) != 0) return -1;
    }

    return write_tag_content(buffer, size, offset, DER_TAG_SEQUENCE, content, c_off);
}

static void bytes_to_hex(char *out, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }
}

static int encode_name(uint8_t *buffer, size_t size, size_t *offset, const cbor_value_t *name) {
    uint8_t text_buf[256];
    size_t text_len = 0;

    if (name->type == CBOR_TYPE_TSTR) {
        text_len = (size_t)name->val;
        memcpy(text_buf, name->ptr, text_len);
    } else if (name->type == CBOR_TYPE_BSTR) {
        if ((size_t)name->val > 0 && name->ptr[0] == 0x00) {
            text_len = ((size_t)name->val - 1) * 2;
            bytes_to_hex((char *)text_buf, name->ptr + 1, (size_t)name->val - 1);
        } else {
            text_len = (size_t)name->val * 2;
            bytes_to_hex((char *)text_buf, name->ptr, (size_t)name->val);
        }
    } else return -1;
    
    uint8_t atv_content[256]; size_t atv_c_off = 0;
    if (write_tag_content(atv_content, sizeof(atv_content), &atv_c_off, DER_TAG_OID, OID_COMMON_NAME, sizeof(OID_COMMON_NAME)) != 0) return -1;
    if (write_tag_content(atv_content, sizeof(atv_content), &atv_c_off, DER_TAG_UTF8_STRING, text_buf, text_len) != 0) return -1;

    uint8_t atv_seq[256]; size_t atv_s_off = 0;
    if (write_tag_content(atv_seq, sizeof(atv_seq), &atv_s_off, DER_TAG_SEQUENCE, atv_content, atv_c_off) != 0) return -1;

    uint8_t rdn_set[256]; size_t rdn_s_off = 0;
    if (write_tag_content(rdn_set, sizeof(rdn_set), &rdn_s_off, DER_TAG_SET, atv_seq, atv_s_off) != 0) return -1;

    return write_tag_content(buffer, size, offset, DER_TAG_SEQUENCE, rdn_set, rdn_s_off);
}

static int encode_ecdsa_signature(uint8_t *buffer, size_t size, size_t *offset, const uint8_t *raw_sig, size_t raw_len) {
    if (raw_len != 64) return -1;
    uint8_t seq_content[128]; size_t s_off = 0;
    if (der_write_integer(seq_content, sizeof(seq_content), &s_off, raw_sig, 32) != 0) return -1;
    if (der_write_integer(seq_content, sizeof(seq_content), &s_off, raw_sig + 32, 32) != 0) return -1;
    return write_tag_content(buffer, size, offset, DER_TAG_SEQUENCE, seq_content, s_off);
}

int x509_encode_full_cert(uint8_t *buffer, size_t size, size_t *offset, const c509_cert_t *cert) {
    uint8_t tbs[1024]; size_t tbs_off = 0;
    
    // 0. Version v3
    uint8_t v_val[3] = { 0x02, 0x01, 0x02 };
    if (write_tag_content(tbs, sizeof(tbs), &tbs_off, 0xA0, v_val, 3) != 0) return -1;

    // 1. Serial
    if (der_write_integer(tbs, sizeof(tbs), &tbs_off, cert->serial.ptr, (size_t)cert->serial.val) != 0) return -1;
    // 2. Sig Alg
    if (encode_alg_id(tbs, sizeof(tbs), &tbs_off, (int64_t)cert->issuer_alg.val) != 0) return -1;
    // 3. Issuer
    if (cert->issuer.type == CBOR_TYPE_SIMPLE && cert->issuer.val == 22) {
        if (encode_name(tbs, sizeof(tbs), &tbs_off, &cert->subject) != 0) return -1;
    } else {
        if (encode_name(tbs, sizeof(tbs), &tbs_off, &cert->issuer) != 0) return -1;
    }
    // 4. Validity
    uint8_t v_content[64]; size_t v_c_off = 0;
    const char *nb_utc = "250102000000Z";
    const char *na_utc = "260102000000Z";
    if (write_tag_content(v_content, sizeof(v_content), &v_c_off, DER_TAG_UTC_TIME, (const uint8_t *)nb_utc, 13) != 0) return -1;
    if (write_tag_content(v_content, sizeof(v_content), &v_c_off, DER_TAG_UTC_TIME, (const uint8_t *)na_utc, 13) != 0) return -1;
    if (write_tag_content(tbs, sizeof(tbs), &tbs_off, DER_TAG_SEQUENCE, v_content, v_c_off) != 0) return -1;

    // 5. Subject
    if (encode_name(tbs, sizeof(tbs), &tbs_off, &cert->subject) != 0) return -1;
    // 6. SPKI
    uint8_t spki_content[256]; size_t spki_c_off = 0;
    if (encode_alg_id(spki_content, sizeof(spki_content), &spki_c_off, 1) != 0) return -1;

    uint8_t pk_raw[66]; size_t pk_raw_len = (size_t)cert->subject_pk.val;
    uint8_t first_byte = cert->subject_pk.ptr[0];
    if (first_byte == 0xFE || first_byte == 0xFD) {
        pk_raw[0] = (first_byte == 0xFE) ? 0x02 : 0x03;
        memcpy(pk_raw + 1, cert->subject_pk.ptr + 1, pk_raw_len - 1);
    } else {
        memcpy(pk_raw, cert->subject_pk.ptr, pk_raw_len);
    }

    uint8_t bitstring[70]; size_t bitstring_off = 0;
    bitstring[bitstring_off++] = 0x00;
    memcpy(bitstring + bitstring_off, pk_raw, pk_raw_len); bitstring_off += pk_raw_len;
    if (write_tag_content(spki_content, sizeof(spki_content), &spki_c_off, DER_TAG_BIT_STRING, bitstring, bitstring_off) != 0) return -1;
    if (write_tag_content(tbs, sizeof(tbs), &tbs_off, DER_TAG_SEQUENCE, spki_content, spki_c_off) != 0) return -1;

    // 7. Extensions
    if (cert->extensions.type == CBOR_TYPE_ARRAY && cert->extensions.val > 0) {
        uint8_t exts_seq_content[512]; size_t exts_s_off = 0;
        cbor_context_t ext_ctx;
        cbor_init(&ext_ctx, cert->extensions.ptr, 1024); // Use large bound, will stop at array end
        
        for (uint64_t i = 0; i < cert->extensions.val / 2; i++) {
            cbor_value_t type_val, value_val;
            if (cbor_decode_next(&ext_ctx, &type_val) != CBOR_ERR_NONE) break;
            if (cbor_decode_next(&ext_ctx, &value_val) != CBOR_ERR_NONE) break;

            int64_t ext_type = (type_val.type == CBOR_TYPE_UINT) ? (int64_t)type_val.val : -(int64_t)(type_val.val + 1);
            
            uint8_t ext_der[256]; size_t ext_d_off = 0;
            if (ext_type == 1) { // SKI
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OID, OID_SKI, sizeof(OID_SKI));
                uint8_t os[64]; size_t os_off = 0;
                write_tag_content(os, sizeof(os), &os_off, DER_TAG_OCTET_STRING, value_val.ptr, (size_t)value_val.val);
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OCTET_STRING, os, os_off);
            } else if (ext_type == 2) { // KeyUsage
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OID, OID_KEY_USAGE, sizeof(OID_KEY_USAGE));
                uint8_t ku_bs[4] = { 0x00, 0x01, (uint8_t)value_val.val };
                uint8_t os[10]; size_t os_off = 0;
                write_tag_content(os, sizeof(os), &os_off, DER_TAG_BIT_STRING, ku_bs + 1, 2);
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OCTET_STRING, os, os_off);
            } else if (ext_type == -4) { // BasicConstraints
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OID, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS));
                uint8_t true_val = 0xFF;
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, 0x01, &true_val, 1); // Critical: TRUE
                uint8_t bc_inner[10]; size_t bc_i_off = 0;
                if (value_val.type == CBOR_TYPE_NINT && value_val.val == 0) { // -1
                    uint8_t bool_tag_val[3] = { 0x01, 0x01, 0xFF };
                    write_tag_content(bc_inner, sizeof(bc_inner), &bc_i_off, DER_TAG_SEQUENCE, bool_tag_val, 3);
                }
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OCTET_STRING, bc_inner, bc_i_off);
            } else if (ext_type == 8) { // EKU
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OID, OID_EKU, sizeof(OID_EKU));
                uint8_t eku_seq[64]; size_t eku_s_off = 0;
                uint8_t eku_oids[64]; size_t eku_o_off = 0;
                write_tag_content(eku_oids, sizeof(eku_oids), &eku_o_off, DER_TAG_OID, OID_SERVER_AUTH, sizeof(OID_SERVER_AUTH));
                write_tag_content(eku_seq, sizeof(eku_seq), &eku_s_off, DER_TAG_SEQUENCE, eku_oids, eku_o_off);
                write_tag_content(ext_der, sizeof(ext_der), &ext_d_off, DER_TAG_OCTET_STRING, eku_seq, eku_s_off);
            }

            if (ext_d_off > 0) {
                write_tag_content(exts_seq_content, sizeof(exts_seq_content), &exts_s_off, DER_TAG_SEQUENCE, ext_der, ext_d_off);
            }
        }

        uint8_t exts_wrap[512]; size_t exts_w_off = 0;
        write_tag_content(exts_wrap, sizeof(exts_wrap), &exts_w_off, DER_TAG_SEQUENCE, exts_seq_content, exts_s_off);
        write_tag_content(tbs, sizeof(tbs), &tbs_off, 0xA3, exts_wrap, exts_w_off);
    }

    // Full Cert
    uint8_t cert_content[1500]; size_t cert_c_off = 0;
    write_tag_content(cert_content, sizeof(cert_content), &cert_c_off, DER_TAG_SEQUENCE, tbs, tbs_off);
    encode_alg_id(cert_content, sizeof(cert_content), &cert_c_off, (int64_t)cert->issuer_alg.val);
    uint8_t sig_der[128]; size_t sig_der_off = 0;
    encode_ecdsa_signature(sig_der, sizeof(sig_der), &sig_der_off, cert->signature.ptr, (size_t)cert->signature.val);
    uint8_t sig_bitstring[160]; size_t sig_bs_off = 0;
    sig_bitstring[sig_bs_off++] = 0x00;
    memcpy(sig_bitstring + sig_bs_off, sig_der, sig_der_off); sig_bs_off += sig_der_off;
    write_tag_content(cert_content, sizeof(cert_content), &cert_c_off, DER_TAG_BIT_STRING, sig_bitstring, sig_bs_off);

    return write_tag_content(buffer, size, offset, DER_TAG_SEQUENCE, cert_content, cert_c_off);
}
