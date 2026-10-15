#include "../diag_files.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static DiagFileStatus preflight(const char* text, DiagProtocol* protocol) {
    return diag_files_test_preflight_nfc((const uint8_t*)text, strlen(text), protocol);
}

static DiagFileStatus preflight_rfid(
    const char* text,
    const char* protocol,
    size_t data_size) {
    return diag_files_test_preflight_rfid(
        (const uint8_t*)text, strlen(text), protocol, data_size);
}

static void append_hex_bytes(char* text, size_t capacity, size_t* used, size_t count) {
    for(size_t i = 0; i < count; ++i) {
        int written = snprintf(text + *used, capacity - *used, "%s00", i ? " " : "");
        assert(written > 0 && (size_t)written < capacity - *used);
        *used += (size_t)written;
    }
    assert(*used + 2u <= capacity);
    text[(*used)++] = '\n';
    text[*used] = '\0';
}

static uint32_t test_read_u32(const uint8_t* data) {
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8u) |
           ((uint32_t)data[2] << 16u) | ((uint32_t)data[3] << 24u);
}

static void test_write_u16(uint8_t* data, uint16_t value) {
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8u);
}

static void test_write_u32(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)value;
    data[1] = (uint8_t)(value >> 8u);
    data[2] = (uint8_t)(value >> 16u);
    data[3] = (uint8_t)(value >> 24u);
}

static uint32_t test_crc32(const uint8_t* data, size_t size) {
    uint32_t crc = UINT32_MAX;
    for(size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for(unsigned bit = 0; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1u) ^ (UINT32_C(0xEDB88320) & mask);
        }
    }
    return ~crc;
}

static void test_refresh_session_crc(uint8_t* encoded) {
    const uint32_t payload_size = test_read_u32(&encoded[12]);
    test_write_u32(&encoded[16], test_crc32(&encoded[20], payload_size));
}

static void test_convert_v2_to_v1(uint8_t* encoded, size_t* encoded_size) {
    enum {
        HeaderSize = 20,
        IdentityUidOffset = 84,
        V1UidBytes = 10,
        V2UidBytes = 32,
    };
    const size_t removed = V2UidBytes - V1UidBytes;
    const uint32_t old_payload_size = test_read_u32(&encoded[12]);
    const size_t tail_offset = HeaderSize + IdentityUidOffset + V2UidBytes;
    memmove(
        &encoded[HeaderSize + IdentityUidOffset + V1UidBytes],
        &encoded[tail_offset],
        *encoded_size - tail_offset);
    *encoded_size -= removed;
    test_write_u16(&encoded[8], 1u);
    test_write_u32(&encoded[12], old_payload_size - (uint32_t)removed);
    test_refresh_session_crc(encoded);
}

static void test_valid_ultralight(void) {
    const char* file =
        "Filetype: Flipper NFC device\n"
        "Version: 2\n"
        "# NFC\n"
        "Device type: NTAG216\n"
        "UID: 04 11 22 33 44 55 66\n"
        "ATQA: 44 00\n"
        "SAK: 00\n"
        "Pages total: 231\n"
        "Page 0: 00 00 00 00\n";
    DiagProtocol protocol = DiagProtocolIso14443_3a;
    assert(preflight(file, &protocol) == DiagFileStatusOk);
    assert(protocol == DiagProtocolMfUltralight);
}

static void test_valid_iso15693(void) {
    const char* file =
        "Filetype: Flipper NFC device\n"
        "Version: 4\n"
        "Device type: ISO15693-3\n"
        "UID: E0 04 01 02 03 04 05 06\n"
        "Block Count: 256\n"
        "Block Size: 04\n";
    DiagProtocol protocol;
    assert(preflight(file, &protocol) == DiagFileStatusOk);
    assert(protocol == DiagProtocolIso15693_3);
}

static void test_preflight_rejections(void) {
    DiagProtocol protocol;
    const char* duplicate_uid =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: ISO14443-3A\n"
        "UID: 01 02 03 04\nUID: 01 02 03 04\nATQA: 04 00\nSAK: 08\n";
    assert(preflight(duplicate_uid, &protocol) == DiagFileStatusInvalidFormat);

    const char* bad_version =
        "Filetype: Flipper NFC device\nVersion: 5\nDevice type: ISO14443-3A\n"
        "UID: 01 02 03 04\nATQA: 04 00\nSAK: 08\n";
    assert(preflight(bad_version, &protocol) == DiagFileStatusInvalidFormat);

    const char* missing_sak =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: ISO14443-3A\n"
        "UID: 01 02 03 04\nATQA: 04 00\n";
    assert(preflight(missing_sak, &protocol) == DiagFileStatusInvalidFormat);

    const char* oversized_pages =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare Ultralight\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 00\nPages total: 511\n";
    assert(preflight(oversized_pages, &protocol) == DiagFileStatusInvalidFormat);

    const char* oversized_memory =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: ISO15693-3\n"
        "UID: E0 04 01 02 03 04 05 06\nBlock Count: 9000\nBlock Size: 04\n";
    assert(preflight(oversized_memory, &protocol) == DiagFileStatusTooLarge);

    const char* oversized_ndef =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Type 4 Tag\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\nNDEF Data Size: 32769\n";
    assert(preflight(oversized_ndef, &protocol) == DiagFileStatusInvalidFormat);

    const char* emv_overflow =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\nPAN length: 11\n";
    assert(preflight(emv_overflow, &protocol) == DiagFileStatusInvalidFormat);

    const uint8_t dummy = 0;
    assert(diag_files_test_preflight_nfc(
               &dummy, DIAG_FILES_MAX_INPUT_SIZE + 1u, &protocol) == DiagFileStatusTooLarge);

    const char* desfire_overflow =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare DESFire\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\nApplication Count: 33\n";
    assert(preflight(desfire_overflow, &protocol) == DiagFileStatusInvalidFormat);

    const char* desfire_zero_picc_keys =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare DESFire\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\nPICC Max Keys: 00\n";
    assert(preflight(desfire_zero_picc_keys, &protocol) == DiagFileStatusInvalidFormat);

    const char* felica_overflow =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: FeliCa\n"
        "UID: 01 02 03 04 05 06 07 08\nBlocks total: 29\n";
    assert(preflight(felica_overflow, &protocol) == DiagFileStatusInvalidFormat);

    const char* desfire_access_overflow =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare DESFire\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Application 010203 File 1 Access Rights: "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n";
    assert(preflight(desfire_access_overflow, &protocol) == DiagFileStatusInvalidFormat);

    const char* desfire_access_29 =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare DESFire\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Application 010203 File 1 Access Rights: "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n";
    assert(preflight(desfire_access_29, &protocol) == DiagFileStatusInvalidFormat);

    const char* desfire_access_odd =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare DESFire\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Application 010203 File 1 Access Rights: 00 00 00\n";
    assert(preflight(desfire_access_odd, &protocol) == DiagFileStatusInvalidFormat);

    const char* desfire_access_valid =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare DESFire\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Application 010203 File 1 Access Rights: 00 00\n";
    assert(preflight(desfire_access_valid, &protocol) == DiagFileStatusOk);

    const char* emv_name_overflow =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Cardholder name: 1234567890123456789012345\n"
        "Application name: 12345678901234567\n";
    assert(preflight(emv_name_overflow, &protocol) == DiagFileStatusInvalidFormat);

    const char* emv_name_boundary =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Cardholder name: 123456789012345678901234\n"
        "Application name: 1234567890123456\n"
        "Application label: 1234567890123456\n";
    assert(preflight(emv_name_boundary, &protocol) == DiagFileStatusOk);

    const char* emv_padded_cardholder =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Cardholder name: X                        \n"
        "Application name: A\nApplication label: B\n";
    assert(preflight(emv_padded_cardholder, &protocol) == DiagFileStatusInvalidFormat);

    const char* emv_padded_application =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Cardholder name: A\nApplication name: X\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n"
        "Application label: B\n";
    assert(preflight(emv_padded_application, &protocol) == DiagFileStatusInvalidFormat);

    const char* emv_missing_application =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Cardholder name: 123456789012345678901234\nApplication label: B\n";
    assert(preflight(emv_missing_application, &protocol) == DiagFileStatusInvalidFormat);

    const char* emv_embedded_cr =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Cardholder\r name: A\nApplication name: B\nApplication label: C\n";
    assert(preflight(emv_embedded_cr, &protocol) == DiagFileStatusInvalidFormat);

    const char* malformed_separator =
        "Filetype:Flipper NFC device\nVersion: 4\nDevice type: ISO15693-3\n"
        "UID: E0 04 01 02 03 04 05 06\n";
    assert(preflight(malformed_separator, &protocol) == DiagFileStatusInvalidFormat);

    const char* classic_short_block =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare Classic\n"
        "UID: 01 02 03 04\nATQA: 04 00\nSAK: 08\nBlock 0: 00\n";
    assert(preflight(classic_short_block, &protocol) == DiagFileStatusInvalidFormat);

    const char* plus_missing_security_level =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare Plus\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "PICC Version: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
        "Card Type: Mifare Plus\nMemory Size: 2K\n";
    assert(preflight(plus_missing_security_level, &protocol) == DiagFileStatusInvalidFormat);

    const char* plus_early_security_level =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare Plus\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Security Level: SL3\n"
        "PICC Version: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
        "Card Type: Mifare Plus\nMemory Size: 2K\n";
    assert(preflight(plus_early_security_level, &protocol) == DiagFileStatusInvalidFormat);

    const char* plus_valid =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare Plus\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "PICC Version: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
        "Card Type: Mifare Plus\nSecurity Level: SL3\nMemory Size: 2K\n";
    assert(preflight(plus_valid, &protocol) == DiagFileStatusOk);
    assert(protocol == DiagProtocolMfPlus);

    const char* plus_invalid_security_level =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: Mifare Plus\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "PICC Version: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
        "Card Type: Mifare Plus\nSecurity Level: invalid\nMemory Size: 2K\n";
    assert(preflight(plus_invalid_security_level, &protocol) == DiagFileStatusInvalidFormat);

    const char* felica_public_block_valid =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: FeliCa\n"
        "UID: 01 02 03 04 05 06 07 08\n"
        "Block 0000: | Service code 000B | Block index 00 | Data: "
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |\n";
    assert(preflight(felica_public_block_valid, &protocol) == DiagFileStatusOk);

    const char* felica_public_block_overflow =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: FeliCa\n"
        "UID: 01 02 03 04 05 06 07 08\n"
        "Block 0000: | Service code 000B | Block index 00 | Data: "
        "000102030405060708090A0B0C0D0E0F1011121314151617\n";
    assert(preflight(felica_public_block_overflow, &protocol) == DiagFileStatusInvalidFormat);

    char oversized_ats[1200] =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: ISO14443-4A\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\nT1...Tk: ";
    size_t ats_size = strlen(oversized_ats);
    append_hex_bytes(oversized_ats, sizeof(oversized_ats), &ats_size, 256u);
    assert(preflight(oversized_ats, &protocol) == DiagFileStatusInvalidFormat);
}

static void test_empty_emv_names(void) {
    const char* file =
        "Filetype: Flipper NFC device\nVersion: 4\nDevice type: EMV\n"
        "UID: 04 01 02 03 04 05 06\nATQA: 44 00\nSAK: 20\n"
        "Cardholder name: \nApplication name: \nApplication label: \nPAN length: 0\n";
    DiagProtocol protocol;
    assert(preflight(file, &protocol) == DiagFileStatusOk);
}

static void test_rfid_preflight(void) {
    const char* valid =
        "Filetype: Flipper RFID key\n"
        "Version: 1\n"
        "# Saved LF data\n"
        "Key type: EM4100\n"
        "Data: 01 02 03 04 05\n";
    assert(preflight_rfid(valid, "EM4100", 5u) == DiagFileStatusOk);
    assert(preflight_rfid(valid, "H10301", 5u) == DiagFileStatusInvalidFormat);
    assert(preflight_rfid(valid, "EM4100", 4u) == DiagFileStatusInvalidFormat);

    const char* duplicate =
        "Filetype: Flipper RFID key\nVersion: 1\nKey type: EM4100\n"
        "Data: 01 02 03 04 05\nData: 01 02 03 04 05\n";
    assert(preflight_rfid(duplicate, "EM4100", 5u) == DiagFileStatusInvalidFormat);

    const char* wrong_version =
        "Filetype: Flipper RFID key\nVersion: 2\nKey type: EM4100\n"
        "Data: 01 02 03 04 05\n";
    assert(preflight_rfid(wrong_version, "EM4100", 5u) == DiagFileStatusInvalidFormat);

    const char* reordered =
        "Filetype: Flipper RFID key\nVersion: 1\nData: 01 02 03 04 05\n"
        "Key type: EM4100\n";
    assert(preflight_rfid(reordered, "EM4100", 5u) == DiagFileStatusInvalidFormat);

    const char* padded_protocol =
        "Filetype: Flipper RFID key\nVersion: 1\nKey type: EM4100 \n"
        "Data: 01 02 03 04 05\n";
    assert(preflight_rfid(padded_protocol, "EM4100", 5u) ==
           DiagFileStatusInvalidFormat);

    const char* embedded_cr =
        "Filetype: Flipper RFID key\nVersion: 1\nKey\r type: EM4100\n"
        "Data: 01 02 03 04 05\n";
    assert(preflight_rfid(embedded_cr, "EM4100", 5u) == DiagFileStatusInvalidFormat);

    char oversized_data[512] =
        "Filetype: Flipper RFID key\nVersion: 1\nKey type: Indala224\nData: ";
    size_t used = strlen(oversized_data);
    append_hex_bytes(oversized_data, sizeof(oversized_data), &used, DIAG_MAX_UID_BYTES + 1u);
    assert(preflight_rfid(oversized_data, "Indala224", DIAG_MAX_UID_BYTES) ==
           DiagFileStatusInvalidFormat);

    uint8_t dummy = 0u;
    assert(diag_files_test_preflight_rfid(
               &dummy, 4097u, "EM4100", 5u) == DiagFileStatusTooLarge);
}

static void test_session_roundtrip(void) {
    DiagModel input;
    diag_model_init(&input, DiagProvenanceLive);
    assert(diag_model_set_timestamp(&input, "2026-10-15T12:34:56Z"));
    const uint8_t uid[] = {0x08, 0x11, 0x22, 0x33};
    const uint8_t atqa[] = {0x04, 0x00};
    assert(diag_model_add_protocol_candidate(&input, DiagProtocolIso14443_3a));
    assert(diag_model_confirm_protocol(&input, DiagProtocolIso14443_3a, true));
    assert(diag_model_set_identity(&input, DiagProtocolIso14443_3a, uid, sizeof(uid)));
    assert(diag_model_set_iso_a_identity(&input, uid, sizeof(uid), atqa, 0));
    assert(diag_model_set_product_metadata(&input, "ISO14443-A", "volatile UID"));
    assert(diag_model_add_log(&input, DiagLogSuccess, DiagStageProtocolRead, "Version read"));
    input.logs_dropped = 3u;
    input.run_succeeded = true;
    input.last_successful_stage = DiagStageComplete;

    uint8_t encoded[DIAG_FILES_MAX_SESSION_PAYLOAD + 20u];
    size_t encoded_size = 0;
    DiagModel output;
    assert(diag_files_test_session_roundtrip(
               &input, &output, encoded, sizeof(encoded), &encoded_size) == DiagFileStatusOk);
    assert(encoded_size <= sizeof(encoded));
    assert(encoded[8] == 2u && encoded[9] == 0u);
    assert(output.provenance == DiagProvenanceSaved);
    assert(output.recorded_provenance == DiagProvenanceLive);
    assert(output.protocols_confirmed & (1u << DiagProtocolIso14443_3a));
    assert(output.protocol_candidates & (1u << DiagProtocolIso14443_3a));
    assert(output.identity.uid_size == sizeof(uid));
    assert(!memcmp(output.identity.uid, uid, sizeof(uid)));
    assert(output.identity.may_randomize);
    assert(output.log_count == 1);
    assert(output.logs_dropped == 3u);

    encoded[encoded_size - 1u] ^= 0x80u;
    assert(diag_files_test_session_decode(encoded, encoded_size, &output) ==
           DiagFileStatusIntegrity);
}

static void test_lf_session_roundtrip(void) {
    DiagModel input;
    diag_model_init(&input, DiagProvenanceLive);
    uint8_t uid[DIAG_MAX_UID_BYTES];
    for(size_t i = 0; i < sizeof(uid); ++i) uid[i] = (uint8_t)(0x80u + i);
    assert(diag_model_add_protocol_candidate(&input, DiagProtocolLfRfid));
    assert(diag_model_confirm_protocol(&input, DiagProtocolLfRfid, true));
    assert(diag_model_set_identity(&input, DiagProtocolLfRfid, uid, sizeof(uid)));
    assert(diag_model_set_product_metadata(&input, "EM4100", "decoded"));
    input.run_succeeded = true;
    input.last_successful_stage = DiagStageComplete;

    uint8_t encoded[DIAG_FILES_MAX_SESSION_PAYLOAD + 20u];
    size_t encoded_size = 0u;
    DiagModel output;
    assert(diag_files_test_session_roundtrip(
               &input, &output, encoded, sizeof(encoded), &encoded_size) == DiagFileStatusOk);
    assert(encoded[8] == 2u && encoded[9] == 0u);
    assert(output.provenance == DiagProvenanceSaved);
    assert(output.recorded_provenance == DiagProvenanceLive);
    assert(output.identity.protocol == DiagProtocolLfRfid);
    assert(output.identity.uid_size == sizeof(uid));
    assert(!memcmp(output.identity.uid, uid, sizeof(uid)));
    assert(output.protocols_confirmed == (UINT32_C(1) << DiagProtocolLfRfid));
    assert(!strcmp(output.metadata.product, "EM4100"));
}

static void test_v1_session_compatibility(void) {
    DiagModel input;
    diag_model_init(&input, DiagProvenanceSimulation);
    const uint8_t uid[] = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    assert(diag_model_add_protocol_candidate(&input, DiagProtocolMfUltralight));
    assert(diag_model_set_identity(&input, DiagProtocolMfUltralight, uid, sizeof(uid)));
    assert(diag_model_set_product_metadata(&input, "NTAG213", "legacy"));

    uint8_t encoded[DIAG_FILES_MAX_SESSION_PAYLOAD + 20u];
    size_t encoded_size = 0u;
    DiagModel scratch;
    assert(diag_files_test_session_roundtrip(
               &input, &scratch, encoded, sizeof(encoded), &encoded_size) == DiagFileStatusOk);
    test_convert_v2_to_v1(encoded, &encoded_size);

    DiagModel output;
    assert(diag_files_test_session_decode(encoded, encoded_size, &output) == DiagFileStatusOk);
    assert(output.provenance == DiagProvenanceSaved);
    assert(output.recorded_provenance == DiagProvenanceSimulation);
    assert(output.identity.protocol == DiagProtocolMfUltralight);
    assert(output.identity.uid_size == sizeof(uid));
    assert(!memcmp(output.identity.uid, uid, sizeof(uid)));
    assert(!strcmp(output.metadata.product, "NTAG213"));

    encoded[20u + 82u] = (uint8_t)DiagProtocolLfRfid;
    test_refresh_session_crc(encoded);
    assert(diag_files_test_session_decode(encoded, encoded_size, &output) ==
           DiagFileStatusIntegrity);
    encoded[20u + 82u] = (uint8_t)DiagProtocolMfUltralight;
    test_write_u32(&encoded[20u + 72u], UINT32_C(1) << DiagProtocolLfRfid);
    test_refresh_session_crc(encoded);
    assert(diag_files_test_session_decode(encoded, encoded_size, &output) ==
           DiagFileStatusIntegrity);
}

static void test_session_invalid_fields(void) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceSaved);
    model.log_count = DIAG_MAX_LOGS + 1u;
    uint8_t encoded[DIAG_FILES_MAX_SESSION_PAYLOAD + 20u];
    size_t encoded_size = 0;
    DiagModel output;
    assert(diag_files_test_session_roundtrip(
               &model, &output, encoded, sizeof(encoded), &encoded_size) ==
           DiagFileStatusInvalidArgument);

    diag_model_init(&model, DiagProvenanceLive);
    model.identity.present = true;
    model.identity.protocol = (DiagProtocol)DIAG_PROTOCOL_COUNT;
    model.identity.uid_size = 1u;
    assert(diag_files_test_session_roundtrip(
               &model, &output, encoded, sizeof(encoded), &encoded_size) ==
           DiagFileStatusInvalidArgument);
    model.identity.protocol = (DiagProtocol)-1;
    assert(diag_files_test_session_roundtrip(
               &model, &output, encoded, sizeof(encoded), &encoded_size) ==
           DiagFileStatusInvalidArgument);
    diag_model_init(&model, DiagProvenanceLive);
    model.protocol_candidates = UINT32_C(1) << DIAG_PROTOCOL_COUNT;
    assert(diag_files_test_session_roundtrip(
               &model, &output, encoded, sizeof(encoded), &encoded_size) ==
           DiagFileStatusInvalidArgument);
}

static void test_heap_guard_math(void) {
    const size_t requested = 16u * 1024u;
    const size_t reserve = 8u * 1024u;
    const size_t allocation = 8u * 1024u;
    const size_t allocation_block = allocation + 8u;
    assert(diag_files_test_heap_sufficient(
        requested + reserve, allocation_block, requested, allocation));
    assert(!diag_files_test_heap_sufficient(
        requested + reserve - 1u, allocation_block, requested, allocation));
    assert(!diag_files_test_heap_sufficient(
        requested + reserve, allocation_block - 1u, requested, allocation));
    assert(!diag_files_test_heap_sufficient(SIZE_MAX, SIZE_MAX, SIZE_MAX, allocation));
    assert(!diag_files_test_heap_sufficient(SIZE_MAX, SIZE_MAX, requested, SIZE_MAX));
}

enum {
    TestFsOk = 0,
    TestFsExist = 2,
    TestFsNotExist = 3,
    TestFsDenied = 5,
    TestFsInvalidName = 6,
};

typedef struct {
    char mkdir_paths[4][DIAG_FILES_PATH_CAPACITY];
    int32_t mkdir_results[4];
    size_t mkdir_count;
    size_t mkdir_result_count;
    bool existing_is_directory;
    bool root_stat_invalid;
    size_t stat_count;
} TestDirectoryStorage;

static int32_t test_directory_mkdir(void* context, const char* path) {
    TestDirectoryStorage* storage = context;
    assert(storage->mkdir_count < 4u);
    snprintf(
        storage->mkdir_paths[storage->mkdir_count],
        sizeof(storage->mkdir_paths[storage->mkdir_count]),
        "%s",
        path);
    const size_t index = storage->mkdir_count++;
    return index < storage->mkdir_result_count ? storage->mkdir_results[index] : TestFsOk;
}

static int32_t test_directory_stat(void* context, const char* path, bool* is_directory) {
    TestDirectoryStorage* storage = context;
    assert(path && *path);
    ++storage->stat_count;
    if(storage->root_stat_invalid && !strcmp(path, "/ext")) return TestFsInvalidName;
    *is_directory = storage->existing_is_directory;
    return TestFsOk;
}

static void test_recursive_export_directory(void) {
    TestDirectoryStorage storage = {
        .mkdir_results = {TestFsOk, TestFsOk},
        .mkdir_result_count = 2u,
        .existing_is_directory = true,
        .root_stat_invalid = true,
    };
    char failed_path[DIAG_FILES_PATH_CAPACITY];
    assert(diag_files_test_ensure_directory(
               "/ext/apps_data/nfc_diagnostic_suite/",
               test_directory_mkdir,
               test_directory_stat,
               &storage,
               TestFsOk,
               TestFsExist,
               TestFsInvalidName,
               failed_path,
               sizeof(failed_path)) == TestFsOk);
    assert(storage.mkdir_count == 2u);
    assert(storage.stat_count == 0u);
    assert(!strcmp(storage.mkdir_paths[0], "/ext/apps_data"));
    assert(!strcmp(storage.mkdir_paths[1], "/ext/apps_data/nfc_diagnostic_suite"));
    assert(!failed_path[0]);

    memset(&storage, 0, sizeof(storage));
    storage.mkdir_results[0] = TestFsExist;
    storage.mkdir_result_count = 1u;
    storage.existing_is_directory = false;
    assert(diag_files_test_ensure_directory(
               "/ext/apps_data",
               test_directory_mkdir,
               test_directory_stat,
               &storage,
               TestFsOk,
               TestFsExist,
               TestFsInvalidName,
               failed_path,
               sizeof(failed_path)) == TestFsInvalidName);
    assert(!strcmp(failed_path, "/ext/apps_data"));

    memset(&storage, 0, sizeof(storage));
    storage.mkdir_results[0] = TestFsDenied;
    storage.mkdir_result_count = 1u;
    assert(diag_files_test_ensure_directory(
               "/ext/apps_data/nfc_diagnostic_suite",
               test_directory_mkdir,
               test_directory_stat,
               &storage,
               TestFsOk,
               TestFsExist,
               TestFsInvalidName,
               failed_path,
               sizeof(failed_path)) == TestFsDenied);
    assert(storage.mkdir_count == 1u);
    assert(!strcmp(failed_path, "/ext/apps_data"));

    memset(&storage, 0, sizeof(storage));
    assert(diag_files_test_ensure_directory(
               "/ext//nfc_diagnostic_suite",
               test_directory_mkdir,
               test_directory_stat,
               &storage,
               TestFsOk,
               TestFsExist,
               TestFsInvalidName,
               failed_path,
               sizeof(failed_path)) == TestFsInvalidName);
}

int main(void) {
    test_valid_ultralight();
    test_valid_iso15693();
    test_preflight_rejections();
    test_empty_emv_names();
    test_rfid_preflight();
    test_session_roundtrip();
    test_lf_session_roundtrip();
    test_v1_session_compatibility();
    test_session_invalid_fields();
    test_heap_guard_math();
    test_recursive_export_directory();
    puts("diag_files tests passed");
    return 0;
}
