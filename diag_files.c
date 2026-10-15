#include "diag_files.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DIAG_FILES_HOST
#include <furi.h>
#include <lfrfid/lfrfid_dict_file.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <nfc/nfc_common.h>
#include <nfc/nfc_device.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <storage/storage.h>
#endif

#define DIAG_NFC_MAX_LINE_SIZE 33024u
#define DIAG_RFID_MAX_INPUT_SIZE 4096u
#define DIAG_RFID_MAX_LINE_SIZE 192u
#define DIAG_SESSION_HEADER_SIZE 20u
#define DIAG_SESSION_VERSION_V1 1u
#define DIAG_SESSION_VERSION 2u
#define DIAG_SESSION_V1_UID_BYTES 10u
#define DIAG_SESSION_MAGIC "NFCDIAG\0"
#define DIAG_HEAP_RESERVE (8u * 1024u)
#define DIAG_NFC_NATIVE_BASE (16u * 1024u)
#define DIAG_NFC_NATIVE_BLOCK (8u * 1024u)
#define DIAG_LF_NATIVE_BASE (16u * 1024u)
#define DIAG_LF_NATIVE_BLOCK (8u * 1024u)
#define DIAG_LINE_INITIAL_CAPACITY 512u
#define DIAG_HEAP_ALIGNMENT 8u
#define DIAG_HEAP_HEADER_SIZE 8u
#define DIAG_VALID_PROTOCOL_MASK ((UINT32_C(1) << DIAG_PROTOCOL_COUNT) - UINT32_C(1))
#define DIAG_VALID_NFC_PROTOCOL_MASK \
    ((UINT32_C(1) << DIAG_NFC_PROTOCOL_COUNT) - UINT32_C(1))

typedef size_t (*DiagRead)(void* context, uint8_t* data, size_t size);

typedef struct {
    DiagRead read;
    void* context;
    size_t remaining;
} DiagInput;

typedef struct {
    bool filetype;
    bool version;
    bool device_type;
    bool uid;
    bool atqa;
    bool sak;
    bool block_count;
    bool block_size;
    bool ndef_size;
    bool pages_total;
    bool pages_read;
    bool emv_cardholder;
    bool emv_application_name;
    bool emv_application_label;
    uint8_t emv_name_stage;
    bool plus_version;
    bool plus_card_type;
    bool plus_security_level;
    bool plus_memory_size;
    uint8_t plus_stage;
    uint32_t format_version;
    DiagProtocol protocol;
    uint8_t uid_data[DIAG_MAX_ISO_A_UID_BYTES];
    size_t uid_size;
    uint8_t atqa_data[2];
    uint8_t sak_data;
    uint32_t block_count_value;
    uint32_t block_size_value;
    uint32_t allocation_budget;
    uint32_t largest_allocation;
    bool low_memory;
} DiagNfcPreflight;

typedef struct {
    char protocol[DIAG_PRODUCT_CAPACITY];
    uint8_t data[DIAG_MAX_UID_BYTES];
    size_t data_size;
    uint32_t format_version;
} DiagRfidPreflight;

typedef struct {
    uint8_t* data;
    size_t capacity;
    size_t position;
    bool failed;
} DiagEncoder;

typedef struct {
    const uint8_t* data;
    size_t size;
    size_t position;
    bool failed;
} DiagDecoder;

static size_t diag_bounded_strlen(const char* text, size_t capacity) {
    size_t size = 0;
    if(!text) return capacity;
    while(size < capacity && text[size]) ++size;
    return size;
}

static bool diag_string_valid(const char* text, size_t capacity) {
    return diag_bounded_strlen(text, capacity) < capacity;
}

static bool diag_size_add(size_t left, size_t right, size_t* result) {
    if(left > SIZE_MAX - right) return false;
    *result = left + right;
    return true;
}

static bool diag_heap_values_sufficient(
    size_t free_heap,
    size_t max_free_block,
    size_t requested_total,
    size_t largest_allocation) {
    size_t total_required;
    if(!diag_size_add(requested_total, DIAG_HEAP_RESERVE, &total_required)) return false;
    size_t block_required = largest_allocation;
    if(block_required) {
        if(!diag_size_add(block_required, DIAG_HEAP_HEADER_SIZE, &block_required)) return false;
        if(block_required > SIZE_MAX - (DIAG_HEAP_ALIGNMENT - 1u)) return false;
        block_required =
            (block_required + DIAG_HEAP_ALIGNMENT - 1u) & ~(DIAG_HEAP_ALIGNMENT - 1u);
    }
    return free_heap >= total_required && max_free_block >= block_required;
}

static bool diag_heap_sufficient(size_t requested_total, size_t largest_allocation) {
#ifdef DIAG_FILES_HOST
    (void)requested_total;
    (void)largest_allocation;
    return true;
#else
    return diag_heap_values_sufficient(
        memmgr_get_free_heap(),
        memmgr_heap_get_max_free_block(),
        requested_total,
        largest_allocation);
#endif
}

static bool diag_identity_size_valid(DiagProtocol protocol, size_t uid_size) {
    return uid_size > 0u &&
           uid_size <=
               (protocol == DiagProtocolLfRfid ? DIAG_MAX_UID_BYTES :
                                                 DIAG_MAX_ISO_A_UID_BYTES);
}

static bool diag_model_valid(const DiagModel* model) {
    if(!model || model->provenance > DiagProvenanceSimulation ||
       model->recorded_provenance > DiagProvenanceSimulation ||
       model->last_successful_stage > DiagStageComplete ||
       (model->protocol_candidates & ~DIAG_VALID_PROTOCOL_MASK) ||
       (model->protocols_confirmed & ~DIAG_VALID_PROTOCOL_MASK) ||
       (model->protocols_confirmed & ~model->protocol_candidates) ||
       (unsigned)model->identity.protocol >= DIAG_PROTOCOL_COUNT ||
       model->iso_a.uid_size > DIAG_MAX_ISO_A_UID_BYTES ||
       model->log_count > DIAG_MAX_LOGS ||
       model->logs_dropped > UINT32_MAX) {
        return false;
    }
    if((model->identity.present &&
        !diag_identity_size_valid(model->identity.protocol, model->identity.uid_size)) ||
       (!model->identity.present && (model->identity.uid_size != 0u || model->identity.may_randomize)) ||
       (model->iso_a.present && model->iso_a.uid_size != 4u && model->iso_a.uid_size != 7u &&
        model->iso_a.uid_size != 10u) ||
       (!model->iso_a.present && model->iso_a.uid_size != 0u)) {
        return false;
    }
    if(model->identity.may_randomize &&
       !((model->identity.protocol == DiagProtocolIso14443_3a &&
          model->identity.uid_size == 4u && model->identity.uid[0] == 0x08u) ||
         model->identity.protocol == DiagProtocolIso14443_3b ||
         model->identity.protocol == DiagProtocolIso14443_4b)) {
        return false;
    }
    if(!diag_string_valid(model->timestamp, sizeof(model->timestamp)) ||
       !diag_string_valid(model->error.domain, sizeof(model->error.domain)) ||
       !diag_string_valid(model->metadata.product, sizeof(model->metadata.product)) ||
       !diag_string_valid(model->metadata.version, sizeof(model->metadata.version)) ||
       !diag_string_valid(model->runtime.firmware_build, sizeof(model->runtime.firmware_build)) ||
       !diag_string_valid(model->runtime.runtime_version, sizeof(model->runtime.runtime_version))) {
        return false;
    }
    for(size_t i = 0; i < model->log_count; ++i) {
        if(model->logs[i].level > DiagLogError || model->logs[i].stage > DiagStageComplete ||
           !diag_string_valid(model->logs[i].message, sizeof(model->logs[i].message))) {
            return false;
        }
    }
    return true;
}

const char* diag_file_status_string(DiagFileStatus status) {
    switch(status) {
    case DiagFileStatusOk:
        return "OK";
    case DiagFileStatusInvalidArgument:
        return "Invalid argument";
    case DiagFileStatusNotFound:
        return "File not found";
    case DiagFileStatusTooLarge:
        return "File exceeds safety limit";
    case DiagFileStatusInvalidFormat:
        return "Invalid file format";
    case DiagFileStatusUnsupported:
        return "Unsupported NFC device type";
    case DiagFileStatusIntegrity:
        return "Checksum or saved data invalid";
    case DiagFileStatusExists:
        return "Destination already exists";
    case DiagFileStatusIo:
        return "Storage error";
    case DiagFileStatusPartial:
        return "Some output files failed";
    default:
        return "Unknown file error";
    }
}

static char* diag_trim(char* text) {
    while(*text == ' ' || *text == '\t') ++text;
    size_t size = strlen(text);
    while(size && (text[size - 1] == ' ' || text[size - 1] == '\t' || text[size - 1] == '\r')) {
        text[--size] = '\0';
    }
    return text;
}

static bool diag_parse_u32(const char* text, uint32_t* value) {
    if(!text || !*text || !value) return false;
    uint64_t parsed = 0;
    for(const char* cursor = text; *cursor; ++cursor) {
        if(*cursor < '0' || *cursor > '9') return false;
        parsed = parsed * 10u + (uint32_t)(*cursor - '0');
        if(parsed > UINT32_MAX) return false;
    }
    *value = (uint32_t)parsed;
    return true;
}

static int diag_hex_nibble(char value) {
    if(value >= '0' && value <= '9') return value - '0';
    if(value >= 'a' && value <= 'f') return value - 'a' + 10;
    if(value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static bool diag_parse_hex(const char* text, uint8_t* output, size_t capacity, size_t* count) {
    size_t parsed = 0;
    while(*text) {
        while(*text == ' ' || *text == '\t') ++text;
        if(!*text) break;
        int high = diag_hex_nibble(*text++);
        if(high < 0 || !*text) return false;
        int low = diag_hex_nibble(*text++);
        if(low < 0 || (*text && *text != ' ' && *text != '\t')) return false;
        if(parsed >= capacity) return false;
        if(output) output[parsed] = (uint8_t)((high << 4) | low);
        ++parsed;
    }
    if(count) *count = parsed;
    return parsed > 0;
}

static bool diag_starts_with(const char* text, const char* prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static bool diag_protocol_from_device_type(const char* name, DiagProtocol* protocol) {
    if(!strcmp(name, "ISO14443-3A")) *protocol = DiagProtocolIso14443_3a;
    else if(!strcmp(name, "ISO14443-3B")) *protocol = DiagProtocolIso14443_3b;
    else if(!strcmp(name, "ISO14443-4A")) *protocol = DiagProtocolIso14443_4a;
    else if(!strcmp(name, "ISO14443-4B")) *protocol = DiagProtocolIso14443_4b;
    else if(!strcmp(name, "ISO15693") || !strcmp(name, "ISO15693-3"))
        *protocol = DiagProtocolIso15693_3;
    else if(diag_starts_with(name, "FeliCa")) *protocol = DiagProtocolFelica;
    else if(diag_starts_with(name, "Mifare Ultralight") || diag_starts_with(name, "NTAG2") ||
            diag_starts_with(name, "NTAG I2C"))
        *protocol = DiagProtocolMfUltralight;
    else if(diag_starts_with(name, "Mifare Classic")) *protocol = DiagProtocolMfClassic;
    else if(diag_starts_with(name, "Mifare Plus")) *protocol = DiagProtocolMfPlus;
    else if(diag_starts_with(name, "Mifare DESFire")) *protocol = DiagProtocolMfDesfire;
    else if(diag_starts_with(name, "SLIX")) *protocol = DiagProtocolSlix;
    else if(diag_starts_with(name, "ST25TB") || diag_starts_with(name, "SRI") ||
            diag_starts_with(name, "SRIX"))
        *protocol = DiagProtocolSt25tb;
    else if(diag_starts_with(name, "NTAG 4") || diag_starts_with(name, "NTAG4"))
        *protocol = DiagProtocolNtag4xx;
    else if(!strcmp(name, "Type 4 Tag")) *protocol = DiagProtocolType4Tag;
    else if(!strcmp(name, "EMV")) *protocol = DiagProtocolEmv;
    else return false;
    return true;
}

static bool diag_protocol_has_iso_a(DiagProtocol protocol) {
    return protocol == DiagProtocolIso14443_3a || protocol == DiagProtocolIso14443_4a ||
           protocol == DiagProtocolMfUltralight || protocol == DiagProtocolMfClassic ||
           protocol == DiagProtocolMfPlus || protocol == DiagProtocolMfDesfire ||
           protocol == DiagProtocolNtag4xx || protocol == DiagProtocolType4Tag ||
           protocol == DiagProtocolEmv;
}

static bool diag_key_ends_with(const char* key, const char* suffix) {
    size_t key_size = strlen(key);
    size_t suffix_size = strlen(suffix);
    return key_size >= suffix_size && !strcmp(key + key_size - suffix_size, suffix);
}

static DiagFileStatus diag_add_allocation(
    DiagNfcPreflight* state,
    uint32_t size,
    uint32_t largest_allocation) {
    if(size > DIAG_FILES_MAX_SESSION_PAYLOAD - state->allocation_budget)
        return DiagFileStatusTooLarge;
    state->allocation_budget += size;
    if(largest_allocation > state->largest_allocation)
        state->largest_allocation = largest_allocation;
    return DiagFileStatusOk;
}

static bool diag_is_desfire_file_data_key(const char* key) {
    if(!diag_starts_with(key, "Application ")) return false;
    const char* file = strstr(key, " File ");
    if(!file) return false;
    file += 6;
    if(!*file) return false;
    while(*file >= '0' && *file <= '9') ++file;
    return *file == '\0';
}

static bool diag_is_classic_block_key(const char* key) {
    if(!diag_starts_with(key, "Block ")) return false;
    key += 6u;
    if(!*key) return false;
    while(*key >= '0' && *key <= '9') ++key;
    return *key == '\0';
}

static bool diag_classic_block_valid(const char* value) {
    if(strlen(value) != 47u) return false;
    for(size_t i = 0; i < 16u; ++i) {
        const size_t offset = i * 3u;
        const bool unknown = value[offset] == '?' && value[offset + 1u] == '?';
        const bool hex = diag_hex_nibble(value[offset]) >= 0 &&
                         diag_hex_nibble(value[offset + 1u]) >= 0;
        if((!unknown && !hex) || (i < 15u && value[offset + 2u] != ' ')) return false;
    }
    return true;
}

static bool diag_is_felica_public_block_key(const char* key) {
    if(!diag_starts_with(key, "Block ") || strlen(key) != 10u) return false;
    for(size_t i = 6u; i < 10u; ++i) {
        if(diag_hex_nibble(key[i]) < 0) return false;
    }
    return true;
}

static bool diag_felica_public_block_valid(const char* value) {
    static const char service_prefix[] = "| Service code ";
    static const char index_prefix[] = " | Block index ";
    static const char data_prefix[] = " | Data: ";
    const size_t expected_size = (sizeof(service_prefix) - 1u) + 4u +
                                 (sizeof(index_prefix) - 1u) + 2u +
                                 (sizeof(data_prefix) - 1u) + 16u * 3u + 1u;
    if(strlen(value) != expected_size) return false;
    if(strncmp(value, service_prefix, sizeof(service_prefix) - 1u)) return false;
    value += sizeof(service_prefix) - 1u;
    for(size_t i = 0; i < 4u; ++i) {
        if(diag_hex_nibble(*value++) < 0) return false;
    }
    if(strncmp(value, index_prefix, sizeof(index_prefix) - 1u)) return false;
    value += sizeof(index_prefix) - 1u;
    for(size_t i = 0; i < 2u; ++i) {
        if(diag_hex_nibble(*value++) < 0) return false;
    }
    if(strncmp(value, data_prefix, sizeof(data_prefix) - 1u)) return false;
    value += sizeof(data_prefix) - 1u;
    for(size_t i = 0; i < 16u; ++i) {
        if(diag_hex_nibble(value[0]) < 0 || diag_hex_nibble(value[1]) < 0 || value[2] != ' ')
            return false;
        value += 3u;
    }
    return value[0] == '|' && value[1] == '\0';
}

static DiagFileStatus diag_preflight_field(
    DiagNfcPreflight* state,
    char* key,
    char* value,
    size_t native_string_size,
    size_t key_index) {
    uint32_t number;
    size_t count;
    if(!strcmp(key, "Filetype")) {
        if(state->filetype || key_index != 0 || strcmp(value, "Flipper NFC device"))
            return DiagFileStatusInvalidFormat;
        state->filetype = true;
    } else if(!strcmp(key, "Version")) {
        if(state->version || key_index != 1 || !diag_parse_u32(value, &number) || number < 2 ||
           number > 4)
            return DiagFileStatusInvalidFormat;
        state->format_version = number;
        state->version = true;
    } else if(!strcmp(key, "Device type")) {
        if(state->device_type) return DiagFileStatusInvalidFormat;
        if(!diag_protocol_from_device_type(value, &state->protocol))
            return DiagFileStatusUnsupported;
        state->device_type = true;
    } else if(!strcmp(key, "UID")) {
        if(state->uid || !diag_parse_hex(
                             value, state->uid_data, sizeof(state->uid_data), &state->uid_size) ||
           (state->uid_size != 4 && state->uid_size != 7 && state->uid_size != 8 &&
            state->uid_size != 10))
            return DiagFileStatusInvalidFormat;
        state->uid = true;
    } else if(!strcmp(key, "ATQA")) {
        if(state->atqa || !diag_parse_hex(value, state->atqa_data, 2, &count) || count != 2)
            return DiagFileStatusInvalidFormat;
        state->atqa = true;
    } else if(!strcmp(key, "SAK")) {
        if(state->sak || !diag_parse_hex(value, &state->sak_data, 1, &count) || count != 1)
            return DiagFileStatusInvalidFormat;
        state->sak = true;
    } else if(state->protocol == DiagProtocolMfPlus && !strcmp(key, "PICC Version")) {
        if(state->plus_version || state->plus_stage != 0u ||
           !diag_parse_hex(value, NULL, 28u, &count) || count != 28u)
            return DiagFileStatusInvalidFormat;
        state->plus_version = true;
        state->plus_stage = 1u;
    } else if(state->protocol == DiagProtocolMfPlus && !strcmp(key, "Card Type")) {
        if(state->plus_card_type || state->plus_stage != 1u)
            return DiagFileStatusInvalidFormat;
        state->plus_card_type = true;
        state->plus_stage = 2u;
    } else if(state->protocol == DiagProtocolMfPlus && !strcmp(key, "Security Level")) {
        if(state->plus_security_level || state->plus_stage != 2u)
            return DiagFileStatusInvalidFormat;
        if(strcmp(value, "SL0") && strcmp(value, "SL1") && strcmp(value, "SL2") &&
           strcmp(value, "SL3") && strcmp(value, "Unknown"))
            return DiagFileStatusInvalidFormat;
        state->plus_security_level = true;
        state->plus_stage = 3u;
    } else if(state->protocol == DiagProtocolMfPlus && !strcmp(key, "Memory Size")) {
        if(state->plus_memory_size || state->plus_stage != 3u)
            return DiagFileStatusInvalidFormat;
        state->plus_memory_size = true;
        state->plus_stage = 4u;
    } else if(state->protocol == DiagProtocolMfClassic && diag_is_classic_block_key(key)) {
        if(!diag_classic_block_valid(value)) return DiagFileStatusInvalidFormat;
    } else if(state->protocol == DiagProtocolFelica && diag_is_felica_public_block_key(key)) {
        if(!diag_felica_public_block_valid(value)) return DiagFileStatusInvalidFormat;
    } else if(!strcmp(key, "Pages total") || !strcmp(key, "Pages read")) {
        bool* seen = !strcmp(key, "Pages total") ? &state->pages_total : &state->pages_read;
        if(*seen || !diag_parse_u32(value, &number) || number > 510u)
            return DiagFileStatusInvalidFormat;
        *seen = true;
    } else if(!strcmp(key, "Block Count")) {
        if(state->block_count || !diag_parse_u32(value, &number) || number > 32768u)
            return DiagFileStatusInvalidFormat;
        state->block_count = true;
        state->block_count_value = number;
    } else if(!strcmp(key, "Block Size")) {
        uint8_t byte;
        if(state->block_size || !diag_parse_hex(value, &byte, 1, &count) || count != 1 || !byte)
            return DiagFileStatusInvalidFormat;
        state->block_size = true;
        state->block_size_value = byte;
    } else if(!strcmp(key, "NDEF Data Size")) {
        if(state->ndef_size || !diag_parse_u32(value, &number) || number > 32768u)
            return DiagFileStatusInvalidFormat;
        state->ndef_size = true;
        return diag_add_allocation(state, number, number);
    } else if(!strcmp(key, "Application Count")) {
        if(!diag_parse_u32(value, &number) || number > 32u) return DiagFileStatusInvalidFormat;
        return diag_add_allocation(state, number * 128u, number * 24u);
    } else if(!strcmp(key, "Application IDs")) {
        uint8_t ids[32u * 3u];
        if(!diag_parse_hex(value, ids, sizeof(ids), &count) || count % 3u)
            return DiagFileStatusInvalidFormat;
        return diag_add_allocation(state, (uint32_t)count, (uint32_t)count);
    } else if(diag_key_ends_with(key, "Max Keys")) {
        uint8_t byte;
        if(!diag_parse_hex(value, &byte, 1, &count) || count != 1 || byte > 14u ||
           (!strcmp(key, "PICC Max Keys") && byte == 0u))
            return DiagFileStatusInvalidFormat;
        return diag_add_allocation(state, byte, byte);
    } else if(diag_key_ends_with(key, "File IDs")) {
        uint8_t ids[32];
        if(!diag_parse_hex(value, ids, sizeof(ids), &count)) return DiagFileStatusInvalidFormat;
        return diag_add_allocation(
            state, (uint32_t)count * 256u, (uint32_t)count * 64u);
    } else if(diag_is_desfire_file_data_key(key)) {
        if(!diag_parse_hex(value, NULL, DIAG_FILES_MAX_SESSION_PAYLOAD, &count))
            return DiagFileStatusInvalidFormat;
        return diag_add_allocation(state, (uint32_t)count, (uint32_t)count);
    } else if(!strcmp(key, "System found")) {
        if(!diag_parse_u32(value, &number) || number > 16u) return DiagFileStatusInvalidFormat;
        return diag_add_allocation(state, number * 256u, number * 256u);
    } else if(!strcmp(key, "Area found") || !strcmp(key, "Service found") ||
              !strcmp(key, "Public blocks read")) {
        if(!diag_parse_u32(value, &number) || number > 255u) return DiagFileStatusInvalidFormat;
        uint32_t item_size = !strcmp(key, "Public blocks read") ? 32u : 16u;
        return diag_add_allocation(state, number * item_size, number * item_size);
    } else if(!strcmp(key, "Blocks total") || !strcmp(key, "Blocks read")) {
        if(!diag_parse_u32(value, &number) || number > 28u) return DiagFileStatusInvalidFormat;
    } else if(!strcmp(key, "Security Status")) {
        if(!diag_parse_hex(value, NULL, DIAG_FILES_MAX_SESSION_PAYLOAD, &count))
            return DiagFileStatusInvalidFormat;
        return diag_add_allocation(state, (uint32_t)count, (uint32_t)count);
    } else if(!strcmp(key, "PAN length")) {
        if(state->protocol == DiagProtocolEmv && state->emv_name_stage != 3u)
            return DiagFileStatusInvalidFormat;
        if(!diag_parse_u32(value, &number) || number > 10u) return DiagFileStatusInvalidFormat;
    } else if(!strcmp(key, "AID length")) {
        if(!diag_parse_u32(value, &number) || number > 16u) return DiagFileStatusInvalidFormat;
    } else if(!strcmp(key, "PIN try counter")) {
        if(!diag_parse_u32(value, &number) || number > UINT8_MAX)
            return DiagFileStatusInvalidFormat;
    } else if(!strcmp(key, "Cardholder name")) {
        if(state->emv_cardholder || state->emv_name_stage != 0u || native_string_size > 24u ||
           !state->device_type || state->protocol != DiagProtocolEmv || !state->uid ||
           !state->atqa || !state->sak)
            return DiagFileStatusInvalidFormat;
        state->emv_cardholder = true;
        state->emv_name_stage = 1u;
    } else if(!strcmp(key, "Application name")) {
        if(state->emv_application_name || state->emv_name_stage != 1u ||
           native_string_size > 16u)
            return DiagFileStatusInvalidFormat;
        state->emv_application_name = true;
        state->emv_name_stage = 2u;
    } else if(!strcmp(key, "Application label")) {
        if(state->emv_application_label || state->emv_name_stage != 2u ||
           native_string_size > 16u)
            return DiagFileStatusInvalidFormat;
        state->emv_application_label = true;
        state->emv_name_stage = 3u;
    } else if(diag_key_ends_with(key, "Access Rights")) {
        if(!diag_parse_hex(value, NULL, 28u, &count) || count < 2u || (count % 2u))
            return DiagFileStatusInvalidFormat;
    } else if(!strcmp(key, "T1...Tk")) {
        if(!diag_parse_hex(value, NULL, 255u, &count)) return DiagFileStatusInvalidFormat;
        return diag_add_allocation(state, (uint32_t)count, (uint32_t)count);
    }
    return DiagFileStatusOk;
}

static DiagFileStatus diag_preflight_input(DiagInput* input, DiagNfcPreflight* result) {
    if(!input || !input->read || !result) return DiagFileStatusInvalidArgument;
    if(input->remaining > DIAG_FILES_MAX_INPUT_SIZE) return DiagFileStatusTooLarge;
    memset(result, 0, sizeof(*result));
    size_t line_capacity = DIAG_LINE_INITIAL_CAPACITY;
    if(!diag_heap_sufficient(line_capacity, line_capacity)) {
        result->low_memory = true;
        return DiagFileStatusTooLarge;
    }
    char* line = malloc(line_capacity);
    if(!line) {
        result->low_memory = true;
        return DiagFileStatusTooLarge;
    }
    size_t line_size = 0;
    size_t key_index = 0;
    DiagFileStatus status = DiagFileStatusOk;
    for(size_t consumed = 0; consumed <= input->remaining;) {
        uint8_t byte = '\n';
        if(consumed < input->remaining) {
            if(input->read(input->context, &byte, 1u) != 1u) {
                status = DiagFileStatusIo;
                break;
            }
            ++consumed;
            if(!byte) {
                status = DiagFileStatusInvalidFormat;
                break;
            }
        } else {
            ++consumed;
        }
        if(byte != '\n') {
            if(line_size == DIAG_NFC_MAX_LINE_SIZE) {
                status = DiagFileStatusTooLarge;
                break;
            }
            if(line_size + 1u >= line_capacity) {
                size_t next_capacity = line_capacity * 2u;
                if(next_capacity > DIAG_NFC_MAX_LINE_SIZE + 1u)
                    next_capacity = DIAG_NFC_MAX_LINE_SIZE + 1u;
                if(!diag_heap_sufficient(next_capacity, next_capacity)) {
                    result->low_memory = true;
                    status = DiagFileStatusTooLarge;
                    break;
                }
                char* grown = malloc(next_capacity);
                if(!grown) {
                    result->low_memory = true;
                    status = DiagFileStatusTooLarge;
                    break;
                }
                memcpy(grown, line, line_size);
                free(line);
                line = grown;
                line_capacity = next_capacity;
            }
            line[line_size++] = (char)byte;
            continue;
        }
        size_t raw_size = line_size;
        line[line_size] = '\0';
        line_size = 0;
        if(raw_size && line[raw_size - 1u] == '\r') line[--raw_size] = '\0';
        if(memchr(line, '\r', raw_size)) {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        char* content = line;
        while(*content == ' ' || *content == '\t') ++content;
        if(!*content || *content == '#') continue;
        if(content != line) {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        char* separator = memchr(line, ':', raw_size);
        if(!separator || separator + 2u > line + raw_size || separator[1] != ' ') {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        *separator = '\0';
        char* key = content;
        size_t native_string_size = (size_t)((line + raw_size) - (separator + 2u));
        char* value = diag_trim(separator + 2u);
        bool empty_emv_name = !*value &&
            (!strcmp(key, "Cardholder name") || !strcmp(key, "Application name") ||
             !strcmp(key, "Application label"));
        if(!*key || (!*value && !empty_emv_name)) {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        status = diag_preflight_field(result, key, value, native_string_size, key_index++);
        if(status != DiagFileStatusOk) break;
    }
    free(line);
    if(status != DiagFileStatusOk) return status;
    if(!result->filetype || !result->version || !result->device_type || !result->uid)
        return DiagFileStatusInvalidFormat;
    if(diag_protocol_has_iso_a(result->protocol) && (!result->atqa || !result->sak))
        return DiagFileStatusInvalidFormat;
    if(result->protocol == DiagProtocolEmv && result->emv_name_stage != 3u)
        return DiagFileStatusInvalidFormat;
    if(result->protocol == DiagProtocolMfPlus && result->plus_stage != 4u)
        return DiagFileStatusInvalidFormat;
    if(result->block_count != result->block_size) return DiagFileStatusInvalidFormat;
    if(result->block_count && result->block_count_value &&
       result->block_size_value > 32768u / result->block_count_value)
        return DiagFileStatusTooLarge;
    if(result->block_count) {
        uint32_t block_allocation =
            result->block_count_value * result->block_size_value + result->block_count_value;
        if(diag_add_allocation(
               result,
               block_allocation,
               result->block_count_value * result->block_size_value) != DiagFileStatusOk)
            return DiagFileStatusTooLarge;
    }
    return DiagFileStatusOk;
}

static DiagFileStatus diag_preflight_rfid_input(
    DiagInput* input,
    DiagRfidPreflight* result) {
    if(!input || !input->read || !result) return DiagFileStatusInvalidArgument;
    if(input->remaining > DIAG_RFID_MAX_INPUT_SIZE) return DiagFileStatusTooLarge;
    char line[DIAG_RFID_MAX_LINE_SIZE + 1u];
    memset(result, 0, sizeof(*result));
    size_t line_size = 0u;
    size_t key_index = 0u;
    DiagFileStatus status = DiagFileStatusOk;
    for(size_t consumed = 0u; consumed <= input->remaining;) {
        uint8_t byte = '\n';
        if(consumed < input->remaining) {
            if(input->read(input->context, &byte, 1u) != 1u) {
                status = DiagFileStatusIo;
                break;
            }
            ++consumed;
            if(!byte) {
                status = DiagFileStatusInvalidFormat;
                break;
            }
        } else {
            ++consumed;
        }
        if(byte != '\n') {
            if(line_size == DIAG_RFID_MAX_LINE_SIZE) {
                status = DiagFileStatusTooLarge;
                break;
            }
            line[line_size++] = (char)byte;
            continue;
        }
        size_t raw_size = line_size;
        line[line_size] = '\0';
        line_size = 0u;
        if(raw_size && line[raw_size - 1u] == '\r') line[--raw_size] = '\0';
        if(memchr(line, '\r', raw_size)) {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        if(!raw_size || line[0] == '#') continue;
        if(line[0] == ' ' || line[0] == '\t') {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        char* separator = memchr(line, ':', raw_size);
        if(!separator || separator + 2u > line + raw_size || separator[1] != ' ') {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        *separator = '\0';
        char* value = separator + 2u;
        const size_t value_size = (size_t)((line + raw_size) - value);
        if(!*line || !*value || value_size != strlen(value) || value[value_size - 1u] == ' ' ||
           value[value_size - 1u] == '\t') {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        if(key_index == 0u) {
            if(strcmp(line, "Filetype") || strcmp(value, "Flipper RFID key")) {
                status = DiagFileStatusInvalidFormat;
                break;
            }
        } else if(key_index == 1u) {
            uint32_t version = 0u;
            if(strcmp(line, "Version") || !diag_parse_u32(value, &version) || version != 1u) {
                status = DiagFileStatusInvalidFormat;
                break;
            }
            result->format_version = version;
        } else if(key_index == 2u) {
            if(strcmp(line, "Key type") || value_size >= sizeof(result->protocol)) {
                status = DiagFileStatusInvalidFormat;
                break;
            }
            memcpy(result->protocol, value, value_size + 1u);
        } else if(key_index == 3u) {
            if(strcmp(line, "Data") ||
               !diag_parse_hex(
                   value, result->data, sizeof(result->data), &result->data_size)) {
                status = DiagFileStatusInvalidFormat;
                break;
            }
        } else {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        ++key_index;
    }
    if(status != DiagFileStatusOk) return status;
    return key_index == 4u ? DiagFileStatusOk : DiagFileStatusInvalidFormat;
}

static void diag_encode_bytes(DiagEncoder* encoder, const void* data, size_t size) {
    if(encoder->failed || size > encoder->capacity - encoder->position) {
        encoder->failed = true;
        return;
    }
    memcpy(encoder->data + encoder->position, data, size);
    encoder->position += size;
}

static void diag_encode_u8(DiagEncoder* encoder, uint8_t value) {
    diag_encode_bytes(encoder, &value, 1u);
}

static void diag_encode_u16(DiagEncoder* encoder, uint16_t value) {
    uint8_t bytes[2] = {(uint8_t)value, (uint8_t)(value >> 8)};
    diag_encode_bytes(encoder, bytes, sizeof(bytes));
}

static void diag_encode_u32(DiagEncoder* encoder, uint32_t value) {
    uint8_t bytes[4] = {
        (uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    diag_encode_bytes(encoder, bytes, sizeof(bytes));
}

static void diag_decode_bytes(DiagDecoder* decoder, void* data, size_t size) {
    if(decoder->failed || size > decoder->size - decoder->position) {
        decoder->failed = true;
        return;
    }
    memcpy(data, decoder->data + decoder->position, size);
    decoder->position += size;
}

static uint8_t diag_decode_u8(DiagDecoder* decoder) {
    uint8_t value = 0;
    diag_decode_bytes(decoder, &value, 1u);
    return value;
}

static uint16_t diag_decode_u16(DiagDecoder* decoder) {
    uint8_t bytes[2] = {0};
    diag_decode_bytes(decoder, bytes, sizeof(bytes));
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint32_t diag_decode_u32(DiagDecoder* decoder) {
    uint8_t bytes[4] = {0};
    diag_decode_bytes(decoder, bytes, sizeof(bytes));
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint32_t diag_crc32(const uint8_t* data, size_t size) {
    uint32_t crc = UINT32_MAX;
    for(size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for(unsigned bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static void diag_encode_model(DiagEncoder* encoder, const DiagModel* model) {
    diag_encode_u8(encoder, (uint8_t)model->recorded_provenance);
    diag_encode_bytes(encoder, model->timestamp, sizeof(model->timestamp));
    diag_encode_u8(encoder, model->run_succeeded ? 1u : 0u);
    diag_encode_u8(encoder, (uint8_t)model->last_successful_stage);
    diag_encode_u8(encoder, model->error.present ? 1u : 0u);
    diag_encode_bytes(encoder, model->error.domain, sizeof(model->error.domain));
    diag_encode_u32(encoder, (uint32_t)model->error.code);
    diag_encode_u32(encoder, model->protocol_candidates);
    diag_encode_u32(encoder, model->protocols_confirmed);
    diag_encode_u8(encoder, model->identity.present ? 1u : 0u);
    diag_encode_u8(encoder, model->identity.may_randomize ? 1u : 0u);
    diag_encode_u8(encoder, (uint8_t)model->identity.protocol);
    diag_encode_u8(encoder, (uint8_t)model->identity.uid_size);
    diag_encode_bytes(encoder, model->identity.uid, sizeof(model->identity.uid));
    diag_encode_u8(encoder, model->iso_a.present ? 1u : 0u);
    diag_encode_u8(encoder, (uint8_t)model->iso_a.uid_size);
    diag_encode_bytes(encoder, model->iso_a.uid, sizeof(model->iso_a.uid));
    diag_encode_bytes(encoder, model->iso_a.atqa, sizeof(model->iso_a.atqa));
    diag_encode_u8(encoder, model->iso_a.sak);
    diag_encode_u8(encoder, model->iso_a.cascade_count);
    diag_encode_bytes(encoder, model->metadata.product, sizeof(model->metadata.product));
    diag_encode_bytes(encoder, model->metadata.version, sizeof(model->metadata.version));
    diag_encode_bytes(encoder, model->runtime.firmware_build, sizeof(model->runtime.firmware_build));
    diag_encode_bytes(encoder, model->runtime.runtime_version, sizeof(model->runtime.runtime_version));
    diag_encode_u16(encoder, (uint16_t)model->log_count);
    diag_encode_u32(encoder, (uint32_t)model->logs_dropped);
    for(size_t i = 0; i < model->log_count; ++i) {
        diag_encode_u8(encoder, (uint8_t)model->logs[i].level);
        diag_encode_u8(encoder, (uint8_t)model->logs[i].stage);
        diag_encode_u32(encoder, model->logs[i].elapsed_ms);
        diag_encode_bytes(encoder, model->logs[i].message, sizeof(model->logs[i].message));
    }
}

static void diag_decode_model(DiagDecoder* decoder, DiagModel* model, uint16_t version) {
    diag_model_init(model, DiagProvenanceSaved);
    model->recorded_provenance = (DiagProvenance)diag_decode_u8(decoder);
    diag_decode_bytes(decoder, model->timestamp, sizeof(model->timestamp));
    uint8_t run_succeeded = diag_decode_u8(decoder);
    if(run_succeeded > 1u) decoder->failed = true;
    model->run_succeeded = run_succeeded != 0;
    model->last_successful_stage = (DiagStage)diag_decode_u8(decoder);
    uint8_t error_present = diag_decode_u8(decoder);
    if(error_present > 1u) decoder->failed = true;
    model->error.present = error_present != 0;
    diag_decode_bytes(decoder, model->error.domain, sizeof(model->error.domain));
    model->error.code = (int32_t)diag_decode_u32(decoder);
    model->protocol_candidates = diag_decode_u32(decoder);
    model->protocols_confirmed = diag_decode_u32(decoder);
    uint8_t identity_present = diag_decode_u8(decoder);
    if(identity_present > 1u) decoder->failed = true;
    model->identity.present = identity_present != 0;
    uint8_t may_randomize = diag_decode_u8(decoder);
    if(may_randomize > 1u) decoder->failed = true;
    model->identity.may_randomize = may_randomize != 0;
    model->identity.protocol = (DiagProtocol)diag_decode_u8(decoder);
    model->identity.uid_size = diag_decode_u8(decoder);
    const size_t identity_uid_bytes =
        version == DIAG_SESSION_VERSION_V1 ? DIAG_SESSION_V1_UID_BYTES :
                                             sizeof(model->identity.uid);
    diag_decode_bytes(decoder, model->identity.uid, identity_uid_bytes);
    uint8_t iso_a_present = diag_decode_u8(decoder);
    if(iso_a_present > 1u) decoder->failed = true;
    model->iso_a.present = iso_a_present != 0;
    model->iso_a.uid_size = diag_decode_u8(decoder);
    diag_decode_bytes(decoder, model->iso_a.uid, sizeof(model->iso_a.uid));
    diag_decode_bytes(decoder, model->iso_a.atqa, sizeof(model->iso_a.atqa));
    model->iso_a.sak = diag_decode_u8(decoder);
    model->iso_a.cascade_count = diag_decode_u8(decoder);
    diag_decode_bytes(decoder, model->metadata.product, sizeof(model->metadata.product));
    diag_decode_bytes(decoder, model->metadata.version, sizeof(model->metadata.version));
    diag_decode_bytes(decoder, model->runtime.firmware_build, sizeof(model->runtime.firmware_build));
    diag_decode_bytes(decoder, model->runtime.runtime_version, sizeof(model->runtime.runtime_version));
    model->log_count = diag_decode_u16(decoder);
    model->logs_dropped = diag_decode_u32(decoder);
    if(model->log_count > DIAG_MAX_LOGS) {
        decoder->failed = true;
        return;
    }
    for(size_t i = 0; i < model->log_count; ++i) {
        model->logs[i].level = (DiagLogLevel)diag_decode_u8(decoder);
        model->logs[i].stage = (DiagStage)diag_decode_u8(decoder);
        model->logs[i].elapsed_ms = diag_decode_u32(decoder);
        diag_decode_bytes(decoder, model->logs[i].message, sizeof(model->logs[i].message));
    }
}

static DiagFileStatus diag_session_encode(
    const DiagModel* model,
    uint8_t* encoded,
    size_t capacity,
    size_t* encoded_size) {
    if(!diag_model_valid(model) || !encoded || !encoded_size || capacity < DIAG_SESSION_HEADER_SIZE)
        return DiagFileStatusInvalidArgument;
    DiagEncoder payload = {
        .data = encoded + DIAG_SESSION_HEADER_SIZE,
        .capacity = capacity - DIAG_SESSION_HEADER_SIZE,
    };
    diag_encode_model(&payload, model);
    if(payload.failed || payload.position > DIAG_FILES_MAX_SESSION_PAYLOAD)
        return DiagFileStatusTooLarge;
    DiagEncoder header = {.data = encoded, .capacity = DIAG_SESSION_HEADER_SIZE};
    diag_encode_bytes(&header, DIAG_SESSION_MAGIC, 8u);
    diag_encode_u16(&header, DIAG_SESSION_VERSION);
    diag_encode_u16(&header, DIAG_SESSION_HEADER_SIZE);
    diag_encode_u32(&header, (uint32_t)payload.position);
    diag_encode_u32(&header, diag_crc32(payload.data, payload.position));
    if(header.failed) return DiagFileStatusTooLarge;
    *encoded_size = DIAG_SESSION_HEADER_SIZE + payload.position;
    return DiagFileStatusOk;
}

static DiagFileStatus diag_session_decode(
    const uint8_t* encoded,
    size_t encoded_size,
    DiagModel* out) {
    if(!encoded || !out) return DiagFileStatusInvalidArgument;
    if(encoded_size > DIAG_FILES_MAX_SESSION_PAYLOAD + DIAG_SESSION_HEADER_SIZE)
        return DiagFileStatusTooLarge;
    if(encoded_size < DIAG_SESSION_HEADER_SIZE || memcmp(encoded, DIAG_SESSION_MAGIC, 8u))
        return DiagFileStatusInvalidFormat;
    DiagDecoder header = {.data = encoded + 8u, .size = DIAG_SESSION_HEADER_SIZE - 8u};
    uint16_t version = diag_decode_u16(&header);
    uint16_t header_size = diag_decode_u16(&header);
    uint32_t payload_size = diag_decode_u32(&header);
    uint32_t expected_crc = diag_decode_u32(&header);
    if(header.failed ||
       (version != DIAG_SESSION_VERSION_V1 && version != DIAG_SESSION_VERSION) ||
       header_size != DIAG_SESSION_HEADER_SIZE)
        return DiagFileStatusUnsupported;
    if(payload_size > DIAG_FILES_MAX_SESSION_PAYLOAD ||
       payload_size != encoded_size - DIAG_SESSION_HEADER_SIZE)
        return payload_size > DIAG_FILES_MAX_SESSION_PAYLOAD ? DiagFileStatusTooLarge :
                                                              DiagFileStatusInvalidFormat;
    const uint8_t* payload = encoded + DIAG_SESSION_HEADER_SIZE;
    if(diag_crc32(payload, payload_size) != expected_crc) return DiagFileStatusIntegrity;
    DiagDecoder decoder = {.data = payload, .size = payload_size};
    diag_decode_model(&decoder, out, version);
    const bool legacy_protocols_valid =
        version != DIAG_SESSION_VERSION_V1 ||
        (((out->protocol_candidates | out->protocols_confirmed) &
          ~DIAG_VALID_NFC_PROTOCOL_MASK) == 0u &&
         (!out->identity.present || out->identity.protocol < DIAG_NFC_PROTOCOL_COUNT));
    if(decoder.failed || decoder.position != decoder.size || !legacy_protocols_valid ||
       !diag_model_valid(out)) {
        diag_model_init(out, DiagProvenanceSaved);
        return DiagFileStatusIntegrity;
    }
    out->provenance = DiagProvenanceSaved;
    return DiagFileStatusOk;
}

#ifdef DIAG_FILES_TESTING
typedef struct {
    const uint8_t* data;
    size_t size;
    size_t position;
} DiagMemoryReader;

static size_t diag_memory_read(void* context, uint8_t* data, size_t size) {
    DiagMemoryReader* reader = context;
    size_t available = reader->size - reader->position;
    if(size > available) size = available;
    memcpy(data, reader->data + reader->position, size);
    reader->position += size;
    return size;
}

DiagFileStatus diag_files_test_preflight_nfc(
    const uint8_t* data,
    size_t size,
    DiagProtocol* protocol) {
    if(!data || !protocol) return DiagFileStatusInvalidArgument;
    DiagMemoryReader reader = {.data = data, .size = size};
    DiagInput input = {.read = diag_memory_read, .context = &reader, .remaining = size};
    DiagNfcPreflight result;
    DiagFileStatus status = diag_preflight_input(&input, &result);
    if(status == DiagFileStatusOk) *protocol = result.protocol;
    return status;
}

DiagFileStatus diag_files_test_preflight_rfid(
    const uint8_t* data,
    size_t size,
    const char* expected_protocol,
    size_t expected_data_size) {
    if(!data || !expected_protocol || !*expected_protocol || !expected_data_size ||
       expected_data_size > DIAG_MAX_UID_BYTES) {
        return DiagFileStatusInvalidArgument;
    }
    DiagMemoryReader reader = {.data = data, .size = size};
    DiagInput input = {.read = diag_memory_read, .context = &reader, .remaining = size};
    DiagRfidPreflight result;
    DiagFileStatus status = diag_preflight_rfid_input(&input, &result);
    if(status != DiagFileStatusOk) return status;
    return !strcmp(result.protocol, expected_protocol) && result.data_size == expected_data_size ?
               DiagFileStatusOk :
               DiagFileStatusInvalidFormat;
}

DiagFileStatus diag_files_test_session_roundtrip(
    const DiagModel* model,
    DiagModel* out,
    uint8_t* encoded,
    size_t encoded_capacity,
    size_t* encoded_size) {
    DiagFileStatus status =
        diag_session_encode(model, encoded, encoded_capacity, encoded_size);
    if(status != DiagFileStatusOk) return status;
    return diag_session_decode(encoded, *encoded_size, out);
}

DiagFileStatus diag_files_test_session_decode(
    const uint8_t* encoded,
    size_t encoded_size,
    DiagModel* out) {
    return diag_session_decode(encoded, encoded_size, out);
}

bool diag_files_test_heap_sufficient(
    size_t free_heap,
    size_t max_free_block,
    size_t requested_total,
    size_t largest_allocation) {
    return diag_heap_values_sufficient(
        free_heap, max_free_block, requested_total, largest_allocation);
}
#endif

#ifndef DIAG_FILES_HOST
static void diag_explain(FuriString* explanation, DiagFileStatus status) {
    if(explanation) furi_string_set(explanation, diag_file_status_string(status));
}

static void diag_explain_low_memory(FuriString* explanation) {
    if(explanation) furi_string_set(explanation, "Low memory");
}

static bool diag_nfc_heap_sufficient(
    const DiagNfcPreflight* left,
    const DiagNfcPreflight* right) {
    size_t requested_total = DIAG_NFC_NATIVE_BASE;
    size_t largest_allocation = DIAG_NFC_NATIVE_BLOCK;
    if(!diag_size_add(requested_total, left->allocation_budget, &requested_total)) return false;
    if(left->largest_allocation > largest_allocation)
        largest_allocation = left->largest_allocation;
    if(right) {
        if(!diag_size_add(requested_total, DIAG_NFC_NATIVE_BASE, &requested_total) ||
           !diag_size_add(requested_total, right->allocation_budget, &requested_total)) {
            return false;
        }
        if(right->largest_allocation > largest_allocation)
            largest_allocation = right->largest_allocation;
    }
    return diag_heap_sufficient(requested_total, largest_allocation);
}

typedef struct {
    File* file;
    uint8_t cache[512];
    size_t position;
    size_t size;
} DiagCachedFileReader;

static size_t diag_file_read_adapter(void* context, uint8_t* data, size_t size) {
    DiagCachedFileReader* reader = context;
    size_t copied = 0;
    while(copied < size) {
        if(reader->position == reader->size) {
            reader->size = storage_file_read(reader->file, reader->cache, sizeof(reader->cache));
            reader->position = 0;
            if(!reader->size) break;
        }
        size_t available = reader->size - reader->position;
        size_t amount = size - copied;
        if(amount > available) amount = available;
        memcpy(data + copied, reader->cache + reader->position, amount);
        reader->position += amount;
        copied += amount;
    }
    return copied;
}

static DiagFileStatus diag_preflight_nfc_file(
    Storage* storage,
    const char* path,
    DiagNfcPreflight* preflight) {
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_close(file);
        storage_file_free(file);
        return DiagFileStatusNotFound;
    }
    const uint64_t size = storage_file_size(file);
    DiagFileStatus status;
    if(size > DIAG_FILES_MAX_INPUT_SIZE || size > SIZE_MAX) {
        status = DiagFileStatusTooLarge;
    } else {
        DiagCachedFileReader reader = {.file = file};
        DiagInput input = {
            .read = diag_file_read_adapter, .context = &reader, .remaining = (size_t)size};
        status = diag_preflight_input(&input, preflight);
    }
    if(!storage_file_close(file) && status == DiagFileStatusOk) status = DiagFileStatusIo;
    storage_file_free(file);
    return status;
}

static DiagFileStatus diag_preflight_rfid_file(
    Storage* storage,
    const char* path,
    DiagRfidPreflight* preflight) {
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_close(file);
        storage_file_free(file);
        return DiagFileStatusNotFound;
    }
    const uint64_t size = storage_file_size(file);
    DiagFileStatus status;
    if(size > DIAG_RFID_MAX_INPUT_SIZE || size > SIZE_MAX) {
        status = DiagFileStatusTooLarge;
    } else {
        DiagCachedFileReader reader = {.file = file};
        DiagInput input = {
            .read = diag_file_read_adapter, .context = &reader, .remaining = (size_t)size};
        status = diag_preflight_rfid_input(&input, preflight);
    }
    if(!storage_file_close(file) && status == DiagFileStatusOk) status = DiagFileStatusIo;
    storage_file_free(file);
    return status;
}

static DiagFileStatus diag_read_entire(
    Storage* storage,
    const char* path,
    size_t limit,
    size_t additional_heap,
    uint8_t** data,
    size_t* size,
    bool* low_memory) {
    if(low_memory) *low_memory = false;
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_close(file);
        storage_file_free(file);
        return DiagFileStatusNotFound;
    }
    uint64_t file_size = storage_file_size(file);
    if(file_size > limit || file_size > SIZE_MAX) {
        storage_file_close(file);
        storage_file_free(file);
        return DiagFileStatusTooLarge;
    }
    size_t requested_total;
    if(!diag_size_add((size_t)file_size, additional_heap, &requested_total) ||
       !diag_heap_sufficient(requested_total, (size_t)file_size)) {
        if(low_memory) *low_memory = true;
        storage_file_close(file);
        storage_file_free(file);
        return DiagFileStatusTooLarge;
    }
    uint8_t* buffer = malloc((size_t)file_size);
    if(file_size && !buffer) {
        if(low_memory) *low_memory = true;
        storage_file_close(file);
        storage_file_free(file);
        return DiagFileStatusTooLarge;
    }
    DiagFileStatus status = DiagFileStatusOk;
    if(file_size && storage_file_read(file, buffer, (size_t)file_size) != file_size)
        status = DiagFileStatusIo;
    if(!storage_file_close(file)) status = DiagFileStatusIo;
    storage_file_free(file);
    if(status != DiagFileStatusOk) {
        free(buffer);
        return status;
    }
    *data = buffer;
    *size = (size_t)file_size;
    return DiagFileStatusOk;
}

static bool diag_protocol_matches(NfcProtocol native, DiagProtocol expected) {
    return native < NfcProtocolNum && (unsigned)native == (unsigned)expected;
}

static bool diag_nfc_device_matches_preflight(
    const NfcDevice* device,
    const DiagNfcPreflight* preflight) {
    if(!diag_protocol_matches(nfc_device_get_protocol(device), preflight->protocol)) return false;
    size_t uid_size = 0u;
    const uint8_t* uid = nfc_device_get_uid(device, &uid_size);
    if(!uid || uid_size != preflight->uid_size ||
       memcmp(uid, preflight->uid_data, uid_size)) {
        return false;
    }
    if(diag_protocol_has_iso_a(preflight->protocol)) {
        const Iso14443_3aData* iso_a =
            nfc_device_get_data(device, NfcProtocolIso14443_3a);
        uint8_t atqa[2];
        iso14443_3a_get_atqa(iso_a, atqa);
        const uint8_t expected_atqa[2] = {
            preflight->format_version > NFC_LSB_ATQA_FORMAT_VERSION ?
                preflight->atqa_data[1] :
                preflight->atqa_data[0],
            preflight->format_version > NFC_LSB_ATQA_FORMAT_VERSION ?
                preflight->atqa_data[0] :
                preflight->atqa_data[1],
        };
        if(memcmp(atqa, expected_atqa, sizeof(atqa)) ||
           iso14443_3a_get_sak(iso_a) != preflight->sak_data) {
            return false;
        }
    }
    return true;
}

DiagFileStatus diag_files_validate_nfc(
    Storage* storage,
    const char* path,
    DiagModel* out,
    FuriString* explanation) {
    if(!storage || !path || !*path || !out) return DiagFileStatusInvalidArgument;
    DiagNfcPreflight preflight = {0};
    DiagFileStatus status = diag_preflight_nfc_file(storage, path, &preflight);
    if(status != DiagFileStatusOk) {
        if(preflight.low_memory) diag_explain_low_memory(explanation);
        else diag_explain(explanation, status);
        return status;
    }
    if(!diag_nfc_heap_sufficient(&preflight, NULL)) {
        diag_explain_low_memory(explanation);
        return DiagFileStatusTooLarge;
    }
    NfcDevice* device = nfc_device_alloc();
    if(!nfc_device_load(device, path)) {
        nfc_device_free(device);
        diag_explain(explanation, DiagFileStatusInvalidFormat);
        return DiagFileStatusInvalidFormat;
    }
    if(!diag_nfc_device_matches_preflight(device, &preflight)) {
        nfc_device_free(device);
        diag_explain(explanation, DiagFileStatusInvalidFormat);
        return DiagFileStatusInvalidFormat;
    }
    size_t uid_size = 0;
    const uint8_t* uid = nfc_device_get_uid(device, &uid_size);
    if(!uid || uid_size > DIAG_MAX_ISO_A_UID_BYTES) {
        nfc_device_free(device);
        diag_explain(explanation, DiagFileStatusInvalidFormat);
        return DiagFileStatusInvalidFormat;
    }
    diag_model_init(out, DiagProvenanceSaved);
    diag_model_add_protocol_candidate(out, preflight.protocol);
    diag_model_set_identity(out, preflight.protocol, uid, uid_size);
    if(diag_protocol_has_iso_a(preflight.protocol)) {
        const Iso14443_3aData* iso_a = (const Iso14443_3aData*)nfc_device_get_data(
            device, NfcProtocolIso14443_3a);
        uint8_t atqa[2];
        iso14443_3a_get_atqa(iso_a, atqa);
        diag_model_set_iso_a_identity(
            out, uid, uid_size, atqa, iso14443_3a_get_sak(iso_a));
    }
    char version[DIAG_VERSION_CAPACITY];
    snprintf(version, sizeof(version), ".nfc format v%lu", (unsigned long)preflight.format_version);
    diag_model_set_product_metadata(
        out, nfc_device_get_name(device, NfcDeviceNameTypeFull), version);
    out->run_succeeded = true;
    out->last_successful_stage = DiagStageComplete;
    diag_model_add_log(out, DiagLogInfo, DiagStageComplete, "Loaded saved .nfc file");
    nfc_device_free(device);
    diag_explain(explanation, DiagFileStatusOk);
    return DiagFileStatusOk;
}

static DiagFileStatus diag_rfid_resolve(
    ProtocolDict* dict,
    const DiagRfidPreflight* preflight,
    ProtocolId* protocol) {
    if(protocol_dict_get_max_data_size(dict) > DIAG_MAX_UID_BYTES)
        return DiagFileStatusTooLarge;
    ProtocolId resolved;
    size_t expected_size;
    if(!strcmp(preflight->protocol, "I40134")) {
        resolved = LFRFIDProtocolIndala26;
        expected_size = 3u;
    } else {
        resolved = protocol_dict_get_protocol_by_name(dict, preflight->protocol);
        if(resolved == PROTOCOL_NO) return DiagFileStatusUnsupported;
        expected_size = protocol_dict_get_data_size(dict, (size_t)resolved);
    }
    if(expected_size == 0u || expected_size > DIAG_MAX_UID_BYTES ||
       preflight->data_size != expected_size) {
        return DiagFileStatusInvalidFormat;
    }
    *protocol = resolved;
    return DiagFileStatusOk;
}

static DiagFileStatus diag_rfid_load_checked(
    ProtocolDict* dict,
    const char* path,
    const DiagRfidPreflight* preflight,
    ProtocolId expected_protocol,
    uint8_t data[DIAG_MAX_UID_BYTES],
    size_t* data_size) {
    const ProtocolId loaded = lfrfid_dict_file_load(dict, path);
    if(loaded == PROTOCOL_NO || loaded != expected_protocol)
        return DiagFileStatusInvalidFormat;
    const size_t loaded_size = protocol_dict_get_data_size(dict, (size_t)loaded);
    if(loaded_size == 0u || loaded_size > DIAG_MAX_UID_BYTES)
        return DiagFileStatusInvalidFormat;
    protocol_dict_get_data(dict, (size_t)loaded, data, DIAG_MAX_UID_BYTES);
    if(strcmp(preflight->protocol, "I40134") &&
       (loaded_size != preflight->data_size || memcmp(data, preflight->data, loaded_size))) {
        return DiagFileStatusIntegrity;
    }
    *data_size = loaded_size;
    return DiagFileStatusOk;
}

DiagFileStatus diag_files_validate_rfid(
    Storage* storage,
    const char* path,
    DiagModel* out,
    FuriString* explanation) {
    if(!storage || !path || !*path || !out) return DiagFileStatusInvalidArgument;
    DiagRfidPreflight preflight;
    DiagFileStatus status = diag_preflight_rfid_file(storage, path, &preflight);
    if(status != DiagFileStatusOk) {
        diag_explain(explanation, status);
        return status;
    }
    if(!diag_heap_sufficient(DIAG_LF_NATIVE_BASE, DIAG_LF_NATIVE_BLOCK)) {
        diag_explain_low_memory(explanation);
        return DiagFileStatusTooLarge;
    }
    ProtocolDict* dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    ProtocolId protocol = PROTOCOL_NO;
    status = diag_rfid_resolve(dict, &preflight, &protocol);
    uint8_t data[DIAG_MAX_UID_BYTES] = {0};
    size_t data_size = 0u;
    if(status == DiagFileStatusOk) {
        status = diag_rfid_load_checked(
            dict, path, &preflight, protocol, data, &data_size);
    }
    if(status == DiagFileStatusOk) {
        diag_model_init(out, DiagProvenanceSaved);
        if(!diag_model_add_protocol_candidate(out, DiagProtocolLfRfid) ||
           !diag_model_set_identity(out, DiagProtocolLfRfid, data, data_size) ||
           !diag_model_set_product_metadata(
               out, protocol_dict_get_name(dict, (size_t)protocol), ".rfid format v1") ||
           !diag_model_add_log(
               out, DiagLogInfo, DiagStageComplete, "Loaded saved .rfid file")) {
            status = DiagFileStatusInvalidFormat;
        } else {
            out->run_succeeded = true;
            out->last_successful_stage = DiagStageComplete;
        }
    }
    protocol_dict_free(dict);
    diag_explain(explanation, status);
    return status;
}

static void diag_saved_comparison_init(DiagSavedComparison* result) {
    memset(result, 0, sizeof(*result));
    result->left_completeness = DiagSavedReadCompletenessUnknown;
    result->right_completeness = DiagSavedReadCompletenessUnknown;
}

DiagFileStatus diag_files_compare_saved_nfc(
    Storage* storage,
    const char* left_path,
    const char* right_path,
    DiagSavedComparison* result,
    FuriString* explanation) {
    if(!storage || !left_path || !*left_path || !right_path || !*right_path || !result)
        return DiagFileStatusInvalidArgument;
    diag_saved_comparison_init(result);
    DiagNfcPreflight left_preflight = {0};
    DiagNfcPreflight right_preflight = {0};
    DiagFileStatus status = diag_preflight_nfc_file(storage, left_path, &left_preflight);
    if(status == DiagFileStatusOk)
        status = diag_preflight_nfc_file(storage, right_path, &right_preflight);
    if(status == DiagFileStatusOk &&
       (uint64_t)left_preflight.allocation_budget + right_preflight.allocation_budget >
           DIAG_FILES_MAX_SESSION_PAYLOAD) {
        status = DiagFileStatusTooLarge;
    }
    bool low_memory = left_preflight.low_memory || right_preflight.low_memory;
    if(status == DiagFileStatusOk &&
       !diag_nfc_heap_sufficient(&left_preflight, &right_preflight)) {
        status = DiagFileStatusTooLarge;
        low_memory = true;
    }
    NfcDevice* left = NULL;
    NfcDevice* right = NULL;
    if(status == DiagFileStatusOk) {
        left = nfc_device_alloc();
        right = nfc_device_alloc();
        if(!left || !right || !nfc_device_load(left, left_path) ||
           !nfc_device_load(right, right_path) ||
           !diag_nfc_device_matches_preflight(left, &left_preflight) ||
           !diag_nfc_device_matches_preflight(right, &right_preflight)) {
            status = DiagFileStatusInvalidFormat;
        }
    }
    if(status == DiagFileStatusOk) {
        result->equal = nfc_device_is_equal(left, right);
        if(nfc_device_get_protocol(left) == NfcProtocolMfClassic) {
            const MfClassicData* data =
                nfc_device_get_data(left, NfcProtocolMfClassic);
            result->left_completeness = mf_classic_is_card_read(data) ?
                DiagSavedReadCompletenessComplete :
                DiagSavedReadCompletenessIncomplete;
        }
        if(nfc_device_get_protocol(right) == NfcProtocolMfClassic) {
            const MfClassicData* data =
                nfc_device_get_data(right, NfcProtocolMfClassic);
            result->right_completeness = mf_classic_is_card_read(data) ?
                DiagSavedReadCompletenessComplete :
                DiagSavedReadCompletenessIncomplete;
        }
        if(result->left_completeness != DiagSavedReadCompletenessUnknown ||
           result->right_completeness != DiagSavedReadCompletenessUnknown) {
            snprintf(
                result->detail,
                sizeof(result->detail),
                result->equal ?
                    "Saved NFC data equal, including Classic read/key masks; completeness is reported separately. No physical credential proof." :
                    "Saved NFC data differ, including Classic read/key masks; completeness is reported separately. No physical credential proof.");
        } else {
            snprintf(
                result->detail,
                sizeof(result->detail),
                result->equal ?
                    "Saved NFC decoded data equal; source read completeness unavailable. No physical credential proof." :
                    "Saved NFC decoded data differ; source read completeness unavailable. No physical credential proof.");
        }
    }
    if(right) nfc_device_free(right);
    if(left) nfc_device_free(left);
    if(low_memory) diag_explain_low_memory(explanation);
    else diag_explain(explanation, status);
    return status;
}

DiagFileStatus diag_files_compare_saved_rfid(
    Storage* storage,
    const char* left_path,
    const char* right_path,
    DiagSavedComparison* result,
    FuriString* explanation) {
    if(!storage || !left_path || !*left_path || !right_path || !*right_path || !result)
        return DiagFileStatusInvalidArgument;
    diag_saved_comparison_init(result);
    DiagRfidPreflight left_preflight;
    DiagRfidPreflight right_preflight;
    DiagFileStatus status = diag_preflight_rfid_file(storage, left_path, &left_preflight);
    if(status == DiagFileStatusOk)
        status = diag_preflight_rfid_file(storage, right_path, &right_preflight);
    ProtocolDict* dict = NULL;
    ProtocolId left_protocol = PROTOCOL_NO;
    ProtocolId right_protocol = PROTOCOL_NO;
    if(status == DiagFileStatusOk) {
        if(!diag_heap_sufficient(DIAG_LF_NATIVE_BASE, DIAG_LF_NATIVE_BLOCK)) {
            diag_explain_low_memory(explanation);
            return DiagFileStatusTooLarge;
        }
        dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    }
    if(status == DiagFileStatusOk)
        status = diag_rfid_resolve(dict, &left_preflight, &left_protocol);
    if(status == DiagFileStatusOk)
        status = diag_rfid_resolve(dict, &right_preflight, &right_protocol);
    uint8_t left_data[DIAG_MAX_UID_BYTES] = {0};
    uint8_t right_data[DIAG_MAX_UID_BYTES] = {0};
    size_t left_size = 0u;
    size_t right_size = 0u;
    if(status == DiagFileStatusOk)
        status = diag_rfid_load_checked(
            dict, left_path, &left_preflight, left_protocol, left_data, &left_size);
    if(status == DiagFileStatusOk)
        status = diag_rfid_load_checked(
            dict, right_path, &right_preflight, right_protocol, right_data, &right_size);
    if(status == DiagFileStatusOk) {
        result->equal = left_protocol == right_protocol && left_size == right_size &&
                        !memcmp(left_data, right_data, left_size);
        result->left_completeness = DiagSavedReadCompletenessUnknown;
        result->right_completeness = DiagSavedReadCompletenessUnknown;
        snprintf(
            result->detail,
            sizeof(result->detail),
            result->equal ?
                "Saved LF protocol and decoded bytes equal; source read completeness unavailable. No physical credential proof." :
                "Saved LF protocol or decoded bytes differ; source read completeness unavailable. No physical credential proof.");
    }
    if(dict) protocol_dict_free(dict);
    diag_explain(explanation, status);
    return status;
}

DiagFileStatus diag_files_save_session(
    Storage* storage,
    const char* path,
    const DiagModel* model,
    FuriString* explanation) {
    if(!storage || !path || !*path || !model) return DiagFileStatusInvalidArgument;
    size_t capacity = DIAG_SESSION_HEADER_SIZE + 512u +
                      DIAG_MAX_LOGS * (DIAG_LOG_MESSAGE_CAPACITY + 6u);
    if(!diag_heap_sufficient(capacity, capacity)) {
        diag_explain_low_memory(explanation);
        return DiagFileStatusTooLarge;
    }
    uint8_t* buffer = malloc(capacity);
    if(!buffer) {
        diag_explain_low_memory(explanation);
        return DiagFileStatusTooLarge;
    }
    size_t size = 0;
    DiagFileStatus status = diag_session_encode(model, buffer, capacity, &size);
    if(status == DiagFileStatusOk) {
        File* file = storage_file_alloc(storage);
        bool created = false;
        if(!storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_NEW)) {
            status = storage_file_get_error(file) == FSE_EXIST ? DiagFileStatusExists :
                                                                DiagFileStatusIo;
        } else {
            created = true;
            if(storage_file_write(file, buffer, size) != size || !storage_file_sync(file))
                status = DiagFileStatusIo;
        }
        if(!storage_file_close(file) && status == DiagFileStatusOk) status = DiagFileStatusIo;
        storage_file_free(file);
        if(created && status != DiagFileStatusOk) storage_simply_remove(storage, path);
    }
    free(buffer);
    diag_explain(explanation, status);
    return status;
}

DiagFileStatus diag_files_load_session(
    Storage* storage,
    const char* path,
    DiagModel* out,
    FuriString* explanation) {
    if(!storage || !path || !*path || !out) return DiagFileStatusInvalidArgument;
    uint8_t* buffer = NULL;
    size_t size = 0;
    bool low_memory = false;
    DiagFileStatus status = diag_read_entire(
        storage,
        path,
        DIAG_FILES_MAX_SESSION_PAYLOAD + DIAG_SESSION_HEADER_SIZE,
        sizeof(DiagModel),
        &buffer,
        &size,
        &low_memory);
    if(status == DiagFileStatusOk) status = diag_session_decode(buffer, size, out);
    free(buffer);
    if(low_memory) diag_explain_low_memory(explanation);
    else diag_explain(explanation, status);
    return status;
}

typedef struct {
    File* file;
    bool failed;
    uint8_t buffer[512];
    size_t used;
} DiagFileWriter;

static bool diag_file_writer_flush(DiagFileWriter* writer) {
    if(writer->failed) return false;
    if(writer->used && storage_file_write(writer->file, writer->buffer, writer->used) != writer->used) {
        writer->failed = true;
        return false;
    }
    writer->used = 0;
    return true;
}

static bool diag_file_writer(const char* data, size_t size, void* context) {
    DiagFileWriter* writer = context;
    while(size && !writer->failed) {
        size_t available = sizeof(writer->buffer) - writer->used;
        if(!available) {
            if(!diag_file_writer_flush(writer)) return false;
            available = sizeof(writer->buffer);
        }
        size_t amount = size < available ? size : available;
        memcpy(writer->buffer + writer->used, data, amount);
        writer->used += amount;
        data += amount;
        size -= amount;
    }
    return !writer->failed;
}

static DiagFileStatus diag_export_one(
    Storage* storage,
    const char* final_path,
    const DiagModel* model,
    bool json) {
    char temp_path[DIAG_FILES_PATH_CAPACITY + 5u];
    int length = snprintf(temp_path, sizeof(temp_path), "%s.tmp", final_path);
    if(length < 0 || (size_t)length >= sizeof(temp_path)) return DiagFileStatusInvalidArgument;
    File* file = storage_file_alloc(storage);
    DiagFileStatus status = DiagFileStatusOk;
    bool created = false;
    if(!storage_file_open(file, temp_path, FSAM_WRITE, FSOM_CREATE_NEW)) {
        status = storage_file_get_error(file) == FSE_EXIST ? DiagFileStatusExists :
                                                            DiagFileStatusIo;
    } else {
        created = true;
        DiagFileWriter writer = {.file = file};
        bool exported = json ? diag_model_export_json(model, diag_file_writer, &writer) :
                               diag_model_export_csv(model, diag_file_writer, &writer);
        if(!exported || !diag_file_writer_flush(&writer) || !storage_file_sync(file))
            status = DiagFileStatusIo;
    }
    if(!storage_file_close(file) && status == DiagFileStatusOk) status = DiagFileStatusIo;
    storage_file_free(file);
    if(status == DiagFileStatusOk) {
        FS_Error error = storage_common_rename_safe(storage, temp_path, final_path);
        if(error != FSE_OK) status = error == FSE_EXIST ? DiagFileStatusExists : DiagFileStatusIo;
    }
    if(created && status != DiagFileStatusOk) storage_simply_remove(storage, temp_path);
    return status;
}

static bool diag_path_exists(Storage* storage, const char* path) {
    FileInfo info;
    return storage_common_stat(storage, path, &info) == FSE_OK;
}

static DiagFileStatus diag_set_export_paths(
    Storage* storage,
    const char* directory,
    const char* basename,
    unsigned suffix,
    DiagFilesExportResult* result) {
    const char* separator = directory[strlen(directory) - 1u] == '/' ? "" : "/";
    char stem[96];
    int stem_size = suffix ? snprintf(stem, sizeof(stem), "%s%u", basename, suffix) :
                             snprintf(stem, sizeof(stem), "%s", basename);
    if(stem_size < 0 || (size_t)stem_size >= sizeof(stem)) return DiagFileStatusInvalidArgument;
    int json_size = snprintf(
        result->json_path, sizeof(result->json_path), "%s%s%s.json", directory, separator, stem);
    int csv_size = snprintf(
        result->csv_path, sizeof(result->csv_path), "%s%s%s.csv", directory, separator, stem);
    int session_size = snprintf(
        result->session_path, sizeof(result->session_path), "%s%s%s.nds", directory, separator, stem);
    if(json_size < 0 || csv_size < 0 || session_size < 0 ||
       (size_t)json_size >= sizeof(result->json_path) ||
       (size_t)csv_size >= sizeof(result->csv_path) ||
       (size_t)session_size >= sizeof(result->session_path))
        return DiagFileStatusInvalidArgument;
    char temp[DIAG_FILES_PATH_CAPACITY + 5u];
    int temp_size = snprintf(temp, sizeof(temp), "%s.tmp", result->json_path);
    if(temp_size < 0 || (size_t)temp_size >= sizeof(temp)) return DiagFileStatusInvalidArgument;
    if(diag_path_exists(storage, result->json_path) || diag_path_exists(storage, result->csv_path) ||
       diag_path_exists(storage, result->session_path) || diag_path_exists(storage, temp))
        return DiagFileStatusExists;
    temp_size = snprintf(temp, sizeof(temp), "%s.tmp", result->csv_path);
    if(temp_size < 0 || (size_t)temp_size >= sizeof(temp)) return DiagFileStatusInvalidArgument;
    return diag_path_exists(storage, temp) ? DiagFileStatusExists : DiagFileStatusOk;
}

DiagFileStatus diag_files_export_reports(
    Storage* storage,
    const char* directory,
    const char* basename,
    const DiagModel* model,
    DiagFilesExportResult* result,
    FuriString* explanation) {
    if(!storage || !directory || !*directory || !basename || !*basename || !model || !result ||
       !diag_model_valid(model) || strchr(basename, '/') || strchr(basename, '\\'))
        return DiagFileStatusInvalidArgument;
    memset(result, 0, sizeof(*result));
    bool paths_found = false;
    for(unsigned suffix = 0; suffix < 1000u; ++suffix) {
        DiagFileStatus path_status =
            diag_set_export_paths(storage, directory, basename, suffix, result);
        if(path_status == DiagFileStatusOk) {
            paths_found = true;
            break;
        }
        if(path_status != DiagFileStatusExists) {
            diag_explain(explanation, path_status);
            return path_status;
        }
    }
    if(!paths_found) {
        diag_explain(explanation, DiagFileStatusExists);
        return DiagFileStatusExists;
    }
    result->json_status = diag_export_one(storage, result->json_path, model, true);
    result->csv_status = diag_export_one(storage, result->csv_path, model, false);
    DiagFileStatus status;
    if(result->json_status == DiagFileStatusOk && result->csv_status == DiagFileStatusOk) {
        status = DiagFileStatusOk;
    } else if(result->json_status == result->csv_status) {
        status = result->json_status;
    } else {
        status = DiagFileStatusPartial;
    }
    diag_explain(explanation, status);
    return status;
}
#endif
