#include "diag_model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const protocol_names[DIAG_PROTOCOL_COUNT] = {
    "ISO14443-3A",
    "ISO14443-3B",
    "ISO14443-4A",
    "ISO14443-4B",
    "ISO15693-3",
    "FeliCa",
    "MIFARE Ultralight",
    "MIFARE Classic",
    "MIFARE Plus",
    "MIFARE DESFire",
    "SLIX",
    "ST25TB",
    "NTAG4xx",
    "Type 4 Tag",
    "EMV",
    "125 kHz RFID",
};

static const DiagProtocolReference protocol_references[DIAG_PROTOCOL_COUNT] = {
    {DiagProtocolIso14443_3a, "ISO14443-3A", "ISO 14443 A", "ISO/IEC 14443-3 Type A", "Anti-collision and UID layer"},
    {DiagProtocolIso14443_3b, "ISO14443-3B", "ISO 14443 B", "ISO/IEC 14443-3 Type B", "Anti-collision and PUPI layer"},
    {DiagProtocolIso14443_4a, "ISO14443-4A", "ISO 14443 A", "ISO/IEC 14443-4 Type A", "Block transport over Type A"},
    {DiagProtocolIso14443_4b, "ISO14443-4B", "ISO 14443 B", "ISO/IEC 14443-4 Type B", "Block transport over Type B"},
    {DiagProtocolIso15693_3, "ISO15693-3", "NFC-V", "ISO/IEC 15693-3", "Vicinity-card inventory and commands"},
    {DiagProtocolFelica, "FeliCa", "NFC-F", "JIS X 6319-4", "FeliCa polling and service access"},
    {DiagProtocolMfUltralight, "MIFARE Ultralight", "MIFARE", "NXP MIFARE Ultralight", "Ultralight-family memory protocol"},
    {DiagProtocolMfClassic, "MIFARE Classic", "MIFARE", "NXP MIFARE Classic", "Classic sector and key protocol"},
    {DiagProtocolMfPlus, "MIFARE Plus", "MIFARE", "NXP MIFARE Plus", "Plus security-level protocol"},
    {DiagProtocolMfDesfire, "MIFARE DESFire", "MIFARE", "NXP MIFARE DESFire", "DESFire application protocol"},
    {DiagProtocolSlix, "SLIX", "NFC-V", "NXP ICODE SLIX", "ICODE SLIX command set"},
    {DiagProtocolSt25tb, "ST25TB", "NFC-B", "STMicroelectronics ST25TB", "ST25TB memory protocol"},
    {DiagProtocolNtag4xx, "NTAG4xx", "NFC-A", "NXP NTAG 4xx", "NTAG 4xx secure tag protocol"},
    {DiagProtocolType4Tag, "Type 4 Tag", "NFC Forum", "NFC Forum Type 4 Tag", "NDEF mapping over ISO-DEP"},
    {DiagProtocolEmv, "EMV", "Payment", "EMV Contactless", "Payment application protocol"},
    {DiagProtocolLfRfid, "125 kHz RFID", "LF RFID", "Protocol-specific 125 kHz RFID", "Decoded LF protocol and identifier"},
};

static bool valid_protocol(DiagProtocol protocol) {
    return (unsigned)protocol < DIAG_PROTOCOL_COUNT;
}

static bool valid_identity_size(DiagProtocol protocol, size_t uid_size) {
    return uid_size > 0u &&
           uid_size <=
               (protocol == DiagProtocolLfRfid ? DIAG_MAX_UID_BYTES :
                                                 DIAG_MAX_ISO_A_UID_BYTES);
}

static bool copy_checked(char* destination, size_t capacity, const char* source) {
    if(!destination || !source || capacity == 0u) return false;
    const size_t length = strlen(source);
    if(length >= capacity) return false;
    memcpy(destination, source, length + 1u);
    return true;
}

static bool bounded_length(const char* text, size_t capacity, size_t* length) {
    if(!text || !length) return false;
    for(size_t index = 0; index < capacity; ++index) {
        if(text[index] == '\0') {
            *length = index;
            return true;
        }
    }
    return false;
}

static bool model_export_valid(const DiagModel* model) {
    const uint32_t valid_protocol_mask =
        (UINT32_C(1) << DIAG_PROTOCOL_COUNT) - UINT32_C(1);
    if(!model || (unsigned)model->provenance > DiagProvenanceSimulation ||
       (unsigned)model->recorded_provenance > DiagProvenanceSimulation ||
       (unsigned)model->last_successful_stage > DiagStageComplete ||
       (model->protocol_candidates & ~valid_protocol_mask) ||
       (model->protocols_confirmed & ~valid_protocol_mask) ||
       (model->protocols_confirmed & ~model->protocol_candidates) ||
       model->log_count > DIAG_MAX_LOGS) {
        return false;
    }
    if(model->identity.present &&
       (!valid_protocol(model->identity.protocol) ||
        !valid_identity_size(model->identity.protocol, model->identity.uid_size))) {
        return false;
    }
    if(model->iso_a.present && model->iso_a.uid_size != 4u &&
       model->iso_a.uid_size != 7u && model->iso_a.uid_size != 10u) {
        return false;
    }
    size_t ignored;
    if(!bounded_length(model->timestamp, sizeof(model->timestamp), &ignored) ||
       !bounded_length(model->error.domain, sizeof(model->error.domain), &ignored) ||
       !bounded_length(model->metadata.product, sizeof(model->metadata.product), &ignored) ||
       !bounded_length(model->metadata.version, sizeof(model->metadata.version), &ignored) ||
       !bounded_length(
           model->runtime.firmware_build, sizeof(model->runtime.firmware_build), &ignored) ||
       !bounded_length(
           model->runtime.runtime_version, sizeof(model->runtime.runtime_version), &ignored)) {
        return false;
    }
    for(size_t index = 0u; index < model->log_count; ++index) {
        if((unsigned)model->logs[index].level > DiagLogError ||
           (unsigned)model->logs[index].stage > DiagStageComplete ||
           !bounded_length(
               model->logs[index].message, sizeof(model->logs[index].message), &ignored)) {
            return false;
        }
    }
    return true;
}

static bool write_data(DiagWriter writer, void* context, const char* data, size_t size) {
    return writer && (size == 0u || writer(data, size, context));
}

static bool write_literal(DiagWriter writer, void* context, const char* literal) {
    return write_data(writer, context, literal, strlen(literal));
}

static bool write_unsigned(DiagWriter writer, void* context, unsigned value) {
    char buffer[16];
    const int length = snprintf(buffer, sizeof(buffer), "%u", value);
    return length > 0 && (size_t)length < sizeof(buffer) &&
           write_data(writer, context, buffer, (size_t)length);
}

static bool write_signed(DiagWriter writer, void* context, int32_t value) {
    char buffer[24];
    const int length = snprintf(buffer, sizeof(buffer), "%ld", (long)value);
    return length > 0 && (size_t)length < sizeof(buffer) &&
           write_data(writer, context, buffer, (size_t)length);
}

static bool write_size(DiagWriter writer, void* context, size_t value) {
    char buffer[24];
    const int length = snprintf(buffer, sizeof(buffer), "%zu", value);
    return length > 0 && (size_t)length < sizeof(buffer) &&
           write_data(writer, context, buffer, (size_t)length);
}

static bool write_json_string_bounded(
    DiagWriter writer,
    void* context,
    const char* value,
    size_t capacity) {
    size_t length = 0u;
    if(!bounded_length(value, capacity, &length) || !write_literal(writer, context, "\"")) {
        return false;
    }

    static const char hex[] = "0123456789ABCDEF";
    for(size_t index = 0; index < length; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if(byte == '"' || byte == '\\') {
            const char escaped[2] = {'\\', (char)byte};
            if(!write_data(writer, context, escaped, sizeof(escaped))) return false;
        } else if(byte == '\b') {
            if(!write_literal(writer, context, "\\b")) return false;
        } else if(byte == '\f') {
            if(!write_literal(writer, context, "\\f")) return false;
        } else if(byte == '\n') {
            if(!write_literal(writer, context, "\\n")) return false;
        } else if(byte == '\r') {
            if(!write_literal(writer, context, "\\r")) return false;
        } else if(byte == '\t') {
            if(!write_literal(writer, context, "\\t")) return false;
        } else if(byte < 0x20u) {
            const char escaped[6] = {'\\', 'u', '0', '0', hex[byte >> 4u], hex[byte & 0x0Fu]};
            if(!write_data(writer, context, escaped, sizeof(escaped))) return false;
        } else if(!write_data(writer, context, (const char*)&value[index], 1u)) {
            return false;
        }
    }
    return write_literal(writer, context, "\"");
}

static bool write_json_string(DiagWriter writer, void* context, const char* value) {
    return write_json_string_bounded(writer, context, value, strlen(value) + 1u);
}

static bool write_csv_string_bounded(
    DiagWriter writer,
    void* context,
    const char* value,
    size_t capacity) {
    size_t length = 0u;
    if(!bounded_length(value, capacity, &length) || !write_literal(writer, context, "\"")) {
        return false;
    }
    for(size_t index = 0; index < length; ++index) {
        if(value[index] == '"' && !write_literal(writer, context, "\"\"")) return false;
        if(value[index] != '"' && !write_data(writer, context, &value[index], 1u)) return false;
    }
    return write_literal(writer, context, "\"");
}

static bool write_hex(DiagWriter writer, void* context, const uint8_t* bytes, size_t size) {
    static const char hex[] = "0123456789ABCDEF";
    for(size_t index = 0; index < size; ++index) {
        const char pair[2] = {hex[bytes[index] >> 4u], hex[bytes[index] & 0x0Fu]};
        if(!write_data(writer, context, pair, sizeof(pair))) return false;
    }
    return true;
}

static bool write_protocols_json(DiagWriter writer, void* context, uint32_t mask) {
    if(!write_literal(writer, context, "[")) return false;
    bool first = true;
    for(unsigned protocol = 0; protocol < DIAG_PROTOCOL_COUNT; ++protocol) {
        if((mask & (UINT32_C(1) << protocol)) == 0u) continue;
        if(!first && !write_literal(writer, context, ",")) return false;
        if(!write_json_string(writer, context, protocol_names[protocol])) return false;
        first = false;
    }
    return write_literal(writer, context, "]");
}

static bool write_protocols_csv(DiagWriter writer, void* context, uint32_t mask) {
    if(!write_literal(writer, context, "\"")) return false;
    bool first = true;
    for(unsigned protocol = 0; protocol < DIAG_PROTOCOL_COUNT; ++protocol) {
        if((mask & (UINT32_C(1) << protocol)) == 0u) continue;
        if(!first && !write_literal(writer, context, "|")) return false;
        if(!write_literal(writer, context, protocol_names[protocol])) return false;
        first = false;
    }
    return write_literal(writer, context, "\"");
}

static bool write_csv_log_fields(
    const DiagLogEntry* entry,
    size_t index,
    DiagWriter writer,
    void* context) {
    if(!write_unsigned(writer, context, (unsigned)index) ||
       !write_literal(writer, context, ",") ||
       !write_unsigned(writer, context, entry->elapsed_ms) ||
       !write_literal(writer, context, ",")) {
        return false;
    }
    const char* level = diag_log_level_name(entry->level);
    const char* stage = diag_stage_name(entry->stage);
    return write_csv_string_bounded(writer, context, level, strlen(level) + 1u) &&
           write_literal(writer, context, ",") &&
           write_csv_string_bounded(writer, context, stage, strlen(stage) + 1u) &&
           write_literal(writer, context, ",") &&
           write_csv_string_bounded(
               writer, context, entry->message, sizeof(entry->message));
}

void diag_model_init(DiagModel* model, DiagProvenance provenance) {
    if(!model) return;
    memset(model, 0, sizeof(*model));
    model->provenance = provenance;
    model->recorded_provenance = provenance;
    model->last_successful_stage = DiagStageNone;
}

bool diag_model_set_timestamp(DiagModel* model, const char* rtc_timestamp) {
    return model && copy_checked(model->timestamp, sizeof(model->timestamp), rtc_timestamp);
}

bool diag_model_add_log(
    DiagModel* model,
    DiagLogLevel level,
    DiagStage stage,
    const char* message) {
    return diag_model_add_log_at(model, level, stage, 0u, message);
}

bool diag_model_add_log_at(
    DiagModel* model,
    DiagLogLevel level,
    DiagStage stage,
    uint32_t elapsed_ms,
    const char* message) {
    if(!model || !message || model->log_count > DIAG_MAX_LOGS) return false;
    DiagLogEntry entry = {0};
    if(!copy_checked(entry.message, sizeof(entry.message), message)) return false;
    entry.level = level;
    entry.stage = stage;
    entry.elapsed_ms = elapsed_ms;
    if(model->log_count == DIAG_MAX_LOGS) {
        memmove(&model->logs[0], &model->logs[1],
                (DIAG_MAX_LOGS - 1u) * sizeof(model->logs[0]));
        if(model->logs_dropped < SIZE_MAX) ++model->logs_dropped;
        model->logs[DIAG_MAX_LOGS - 1u] = entry;
    } else {
        model->logs[model->log_count++] = entry;
    }
    return true;
}

void diag_model_mark_stage_success(DiagModel* model, DiagStage stage) {
    if(!model || (unsigned)stage > (unsigned)DiagStageComplete) return;
    model->last_successful_stage = stage;
    if(stage == DiagStageComplete) model->run_succeeded = true;
}

bool diag_model_set_error(DiagModel* model, const char* domain, int32_t code) {
    if(!model || !domain) return false;
    char checked[DIAG_ERROR_DOMAIN_CAPACITY] = {0};
    if(!copy_checked(checked, sizeof(checked), domain)) return false;
    model->error.present = true;
    memcpy(model->error.domain, checked, sizeof(checked));
    model->error.code = code;
    model->run_succeeded = false;
    return true;
}

void diag_model_clear_error(DiagModel* model) {
    if(!model) return;
    memset(&model->error, 0, sizeof(model->error));
}

bool diag_model_add_protocol_candidate(DiagModel* model, DiagProtocol protocol) {
    if(!model || !valid_protocol(protocol)) return false;
    model->protocol_candidates |= UINT32_C(1) << (unsigned)protocol;
    return true;
}

bool diag_model_confirm_protocol(
    DiagModel* model,
    DiagProtocol protocol,
    bool has_direct_api_evidence) {
    if(!model || !valid_protocol(protocol) || model->provenance != DiagProvenanceLive ||
       !has_direct_api_evidence) {
        return false;
    }
    model->protocol_candidates |= UINT32_C(1) << (unsigned)protocol;
    model->protocols_confirmed |= UINT32_C(1) << (unsigned)protocol;
    return true;
}

bool diag_model_set_iso_a_identity(
    DiagModel* model,
    const uint8_t* uid,
    size_t uid_size,
    const uint8_t atqa[2],
    uint8_t sak) {
    if(!model || !uid || !atqa || (uid_size != 4u && uid_size != 7u && uid_size != 10u)) {
        return false;
    }
    DiagIsoAIdentity identity = {0};
    identity.present = true;
    memcpy(identity.uid, uid, uid_size);
    identity.uid_size = uid_size;
    memcpy(identity.atqa, atqa, sizeof(identity.atqa));
    identity.sak = sak;
    identity.cascade_count = (uint8_t)(uid_size == 4u ? 1u : (uid_size == 7u ? 2u : 3u));
    model->iso_a = identity;
    return true;
}

bool diag_model_set_identity(
    DiagModel* model,
    DiagProtocol protocol,
    const uint8_t* uid,
    size_t uid_size) {
    if(!model || !valid_protocol(protocol) || !uid ||
       !valid_identity_size(protocol, uid_size)) {
        return false;
    }
    DiagIdentity identity = {0};
    identity.present = true;
    identity.protocol = protocol;
    identity.uid_size = uid_size;
    memcpy(identity.uid, uid, uid_size);
    identity.may_randomize =
        (protocol == DiagProtocolIso14443_3a && uid_size == 4u && uid[0] == 0x08u) ||
        protocol == DiagProtocolIso14443_3b || protocol == DiagProtocolIso14443_4b;
    model->identity = identity;
    return true;
}

bool diag_model_set_product_metadata(
    DiagModel* model,
    const char* product,
    const char* version) {
    if(!model || !product || !version) return false;
    DiagProductMetadata metadata = {0};
    if(!copy_checked(metadata.product, sizeof(metadata.product), product) ||
       !copy_checked(metadata.version, sizeof(metadata.version), version)) {
        return false;
    }
    model->metadata = metadata;
    return true;
}

bool diag_model_set_runtime_provenance(
    DiagModel* model,
    const char* firmware_build,
    const char* runtime_version) {
    if(!model || !firmware_build || !runtime_version) return false;
    DiagRuntimeProvenance runtime = {0};
    if(!copy_checked(runtime.firmware_build, sizeof(runtime.firmware_build), firmware_build) ||
       !copy_checked(runtime.runtime_version, sizeof(runtime.runtime_version), runtime_version)) {
        return false;
    }
    model->runtime = runtime;
    return true;
}

const char* diag_protocol_name(DiagProtocol protocol) {
    return valid_protocol(protocol) ? protocol_names[(unsigned)protocol] : "Invalid";
}

const char* diag_provenance_name(DiagProvenance provenance) {
    switch(provenance) {
    case DiagProvenanceLive:
        return "Live";
    case DiagProvenanceSaved:
        return "Saved";
    case DiagProvenanceSimulation:
        return "Simulation";
    default:
        return "Invalid";
    }
}

const char* diag_stage_name(DiagStage stage) {
    switch(stage) {
    case DiagStageNone:
        return "None";
    case DiagStageFieldStarted:
        return "Scan started";
    case DiagStageTechnologyDetected:
        return "Technology detected";
    case DiagStageIdentityRead:
        return "Identity read";
    case DiagStageProtocolRead:
        return "Protocol read";
    case DiagStageMetadataRead:
        return "Metadata read";
    case DiagStageComplete:
        return "Complete";
    default:
        return "Invalid";
    }
}

const char* diag_log_level_name(DiagLogLevel level) {
    switch(level) {
    case DiagLogInfo:
        return "Info";
    case DiagLogSuccess:
        return "Success";
    case DiagLogWarning:
        return "Warning";
    case DiagLogError:
        return "Error";
    default:
        return "Invalid";
    }
}

const DiagProtocolReference* diag_protocol_reference(DiagProtocol protocol) {
    return valid_protocol(protocol) ? &protocol_references[(unsigned)protocol] : NULL;
}

const char* diag_stage_advice(DiagStage stage) {
    switch(stage) {
    case DiagStageNone:
        return "Start a scan and hold the tag near the NFC antenna.";
    case DiagStageFieldStarted:
        return "No technology response; reposition the tag and retry.";
    case DiagStageTechnologyDetected:
        return "Technology responded but identity read failed; retry with one tag present.";
    case DiagStageIdentityRead:
        return "Identity read; inspect protocol poller error domain and code.";
    case DiagStageProtocolRead:
        return "Protocol read succeeded; inspect product metadata read.";
    case DiagStageMetadataRead:
        return "Metadata read succeeded; inspect finalization or storage handling.";
    case DiagStageComplete:
        return "Read completed; repeat five runs to check stability.";
    default:
        return "Unknown stage; preserve the exact error domain and code.";
    }
}

static bool iso_identity_same(const DiagIsoAIdentity* left, const DiagIsoAIdentity* right) {
    if(left->present != right->present) return false;
    if(!left->present) return true;
    const bool left_size_valid = left->uid_size == 4u || left->uid_size == 7u ||
                                 left->uid_size == 10u;
    const bool right_size_valid = right->uid_size == 4u || right->uid_size == 7u ||
                                  right->uid_size == 10u;
    return left_size_valid && right_size_valid &&
           left->uid_size == right->uid_size &&
           memcmp(left->uid, right->uid, left->uid_size) == 0;
}

static bool identity_same(const DiagIdentity* left, const DiagIdentity* right) {
    if(left->present != right->present) return false;
    if(!left->present) return true;
    return left->protocol == right->protocol &&
           left->may_randomize == right->may_randomize &&
           valid_protocol(left->protocol) && right->protocol == left->protocol &&
           left->uid_size == right->uid_size &&
           valid_identity_size(left->protocol, left->uid_size) &&
           memcmp(left->uid, right->uid, left->uid_size) == 0;
}

static bool iso_metadata_same(const DiagIsoAIdentity* left, const DiagIsoAIdentity* right) {
    if(left->present != right->present) return false;
    if(!left->present) return true;
    return memcmp(left->atqa, right->atqa, sizeof(left->atqa)) == 0 &&
           left->sak == right->sak && left->cascade_count == right->cascade_count;
}

static bool error_same(const DiagError* left, const DiagError* right) {
    if(left->present != right->present) return false;
    if(!left->present) return true;
    return left->code == right->code &&
           strncmp(left->domain, right->domain, DIAG_ERROR_DOMAIN_CAPACITY) == 0;
}

static bool product_metadata_same(
    const DiagProductMetadata* left,
    const DiagProductMetadata* right) {
    return strncmp(left->product, right->product, DIAG_PRODUCT_CAPACITY) == 0 &&
           strncmp(left->version, right->version, DIAG_VERSION_CAPACITY) == 0;
}

DiagComparison diag_model_compare(const DiagModel* left, const DiagModel* right) {
    DiagComparison result = {0};
    if(!left || !right) return result;
    const bool identity_observed = (left->identity.present || left->iso_a.present) &&
                                   (right->identity.present || right->iso_a.present);
    result.identity_same = identity_observed &&
                           identity_same(&left->identity, &right->identity) &&
                           iso_identity_same(&left->iso_a, &right->iso_a);
    result.protocols_same = left->protocol_candidates == right->protocol_candidates &&
                            left->protocols_confirmed == right->protocols_confirmed;
    const bool metadata_observed =
        (left->iso_a.present || left->metadata.product[0] != '\0' ||
         left->metadata.version[0] != '\0') &&
        (right->iso_a.present || right->metadata.product[0] != '\0' ||
         right->metadata.version[0] != '\0');
    result.metadata_same = metadata_observed &&
                           iso_metadata_same(&left->iso_a, &right->iso_a) &&
                           product_metadata_same(&left->metadata, &right->metadata);
    result.outcome_same = left->run_succeeded == right->run_succeeded &&
                          left->last_successful_stage == right->last_successful_stage &&
                          error_same(&left->error, &right->error);
    return result;
}

bool diag_model_observe(const DiagModel* model, DiagObservation* observation) {
    const bool identity_valid = !model || !model->identity.present ||
        (valid_protocol(model->identity.protocol) &&
         valid_identity_size(model->identity.protocol, model->identity.uid_size));
    const bool iso_size_valid = !model || !model->iso_a.present ||
        model->iso_a.uid_size == 4u || model->iso_a.uid_size == 7u ||
        model->iso_a.uid_size == 10u;
    if(!model || !observation || !identity_valid || !iso_size_valid) {
        return false;
    }
    memset(observation, 0, sizeof(*observation));
    observation->run_succeeded = model->run_succeeded;
    observation->last_successful_stage = model->last_successful_stage;
    observation->error = model->error;
    observation->protocol_candidates = model->protocol_candidates;
    observation->protocols_confirmed = model->protocols_confirmed;
    observation->identity = model->identity;
    observation->iso_a = model->iso_a;
    observation->metadata = model->metadata;
    return true;
}

DiagComparison diag_observation_compare(
    const DiagObservation* left,
    const DiagObservation* right) {
    DiagComparison result = {0};
    if(!left || !right) return result;
    const bool identity_observed = (left->identity.present || left->iso_a.present) &&
                                   (right->identity.present || right->iso_a.present);
    result.identity_same = identity_observed &&
                           identity_same(&left->identity, &right->identity) &&
                           iso_identity_same(&left->iso_a, &right->iso_a);
    result.protocols_same = left->protocol_candidates == right->protocol_candidates &&
                            left->protocols_confirmed == right->protocols_confirmed;
    const bool metadata_observed =
        (left->iso_a.present || left->metadata.product[0] != '\0' ||
         left->metadata.version[0] != '\0') &&
        (right->iso_a.present || right->metadata.product[0] != '\0' ||
         right->metadata.version[0] != '\0');
    result.metadata_same = metadata_observed &&
                           iso_metadata_same(&left->iso_a, &right->iso_a) &&
                           product_metadata_same(&left->metadata, &right->metadata);
    result.outcome_same = left->run_succeeded == right->run_succeeded &&
                          left->last_successful_stage == right->last_successful_stage &&
                          error_same(&left->error, &right->error);
    return result;
}

bool diag_observations_analyze(
    const DiagObservation observations[DIAG_REPEATABILITY_RUNS],
    DiagRepeatability* result) {
    if(!observations || !result) return false;
    memset(result, 0, sizeof(*result));
    result->run_count = DIAG_REPEATABILITY_RUNS;
    result->identity_repeatable = true;
    result->protocols_repeatable = true;
    result->metadata_repeatable = true;
    result->outcome_repeatable = true;

    for(size_t index = 0; index < DIAG_REPEATABILITY_RUNS; ++index) {
        const DiagObservation* observation = &observations[index];
        if((observation->identity.present &&
            (!valid_protocol(observation->identity.protocol) ||
             !valid_identity_size(
                 observation->identity.protocol, observation->identity.uid_size))) ||
           observation->iso_a.uid_size > DIAG_MAX_ISO_A_UID_BYTES) {
            return false;
        }
        if(observation->run_succeeded) ++result->successful_runs;
        else ++result->failed_runs;
        if(observation->identity.present || observation->iso_a.present) {
            ++result->identity_observed_runs;
        }
        if(observation->protocol_candidates != 0u || observation->protocols_confirmed != 0u) {
            ++result->protocol_observed_runs;
        }
        if(observation->iso_a.present || observation->metadata.product[0] != '\0' ||
           observation->metadata.version[0] != '\0') {
            ++result->metadata_observed_runs;
        }
        if(index > 0u) {
            const DiagComparison comparison =
                diag_observation_compare(&observations[0], observation);
            result->identity_repeatable &= comparison.identity_same;
            result->protocols_repeatable &= comparison.protocols_same;
            result->metadata_repeatable &= comparison.metadata_same;
            result->outcome_repeatable &= comparison.outcome_same;
        }
    }

    result->identity_repeatable &= result->identity_observed_runs == DIAG_REPEATABILITY_RUNS;
    result->protocols_repeatable &= result->protocol_observed_runs == DIAG_REPEATABILITY_RUNS;
    result->metadata_repeatable &= result->metadata_observed_runs == DIAG_REPEATABILITY_RUNS;
    return true;
}

bool diag_repeatability_analyze(
    const DiagModel* const runs[DIAG_REPEATABILITY_RUNS],
    DiagRepeatability* result) {
    if(!runs || !result) return false;
    for(size_t index = 0; index < DIAG_REPEATABILITY_RUNS; ++index) {
        if(!runs[index]) return false;
    }

    DiagObservation observations[DIAG_REPEATABILITY_RUNS];
    for(size_t index = 0; index < DIAG_REPEATABILITY_RUNS; ++index) {
        if(!diag_model_observe(runs[index], &observations[index])) return false;
    }
    return diag_observations_analyze(observations, result);
}

bool diag_model_export_json(const DiagModel* model, DiagWriter writer, void* context) {
    if(!writer || !model_export_valid(model)) return false;

#define JSON_LITERAL(value) \
    do { \
        if(!write_literal(writer, context, value)) return false; \
    } while(0)
    JSON_LITERAL("{\"timestamp\":");
    if(!write_json_string_bounded(writer, context, model->timestamp, sizeof(model->timestamp))) return false;
    JSON_LITERAL(",\"provenance\":");
    if(!write_json_string(writer, context, diag_provenance_name(model->provenance))) return false;
    JSON_LITERAL(",\"recorded_provenance\":");
    if(!write_json_string(writer, context, diag_provenance_name(model->recorded_provenance))) {
        return false;
    }
    JSON_LITERAL(",\"run_succeeded\":");
    JSON_LITERAL(model->run_succeeded ? "true" : "false");
    JSON_LITERAL(",\"last_successful_stage\":");
    if(!write_json_string(writer, context, diag_stage_name(model->last_successful_stage))) return false;
    JSON_LITERAL(",\"error\":");
    if(model->error.present) {
        JSON_LITERAL("{\"domain\":");
        if(!write_json_string_bounded(
               writer, context, model->error.domain, sizeof(model->error.domain))) {
            return false;
        }
        JSON_LITERAL(",\"code\":");
        if(!write_signed(writer, context, model->error.code)) return false;
        JSON_LITERAL("}");
    } else {
        JSON_LITERAL("null");
    }
    JSON_LITERAL(",\"protocol_candidates\":");
    if(!write_protocols_json(writer, context, model->protocol_candidates)) return false;
    JSON_LITERAL(",\"protocols_confirmed\":");
    if(!write_protocols_json(writer, context, model->protocols_confirmed)) return false;
    JSON_LITERAL(",\"identity\":");
    if(model->identity.present) {
        JSON_LITERAL("{\"protocol\":");
        if(!write_json_string(writer, context, diag_protocol_name(model->identity.protocol))) {
            return false;
        }
        JSON_LITERAL(",\"uid\":\"");
        if(!write_hex(writer, context, model->identity.uid, model->identity.uid_size)) return false;
        JSON_LITERAL("\",\"may_randomize\":");
        JSON_LITERAL(model->identity.may_randomize ? "true" : "false");
        JSON_LITERAL("}");
    } else {
        JSON_LITERAL("null");
    }
    JSON_LITERAL(",\"iso_a\":");
    if(model->iso_a.present) {
        JSON_LITERAL("{\"uid\":\"");
        if(!write_hex(writer, context, model->iso_a.uid, model->iso_a.uid_size)) return false;
        JSON_LITERAL("\",\"atqa\":\"");
        if(!write_hex(writer, context, model->iso_a.atqa, sizeof(model->iso_a.atqa))) return false;
        JSON_LITERAL("\",\"sak\":");
        if(!write_unsigned(writer, context, model->iso_a.sak)) return false;
        JSON_LITERAL(",\"cascade_count\":{\"value\":");
        if(!write_unsigned(writer, context, model->iso_a.cascade_count)) return false;
        JSON_LITERAL(",\"evidence\":\"DERIVED\"}}");
    } else {
        JSON_LITERAL("null");
    }
    JSON_LITERAL(",\"metadata\":{\"product\":");
    if(!write_json_string_bounded(
           writer, context, model->metadata.product, sizeof(model->metadata.product))) {
        return false;
    }
    JSON_LITERAL(",\"version\":");
    if(!write_json_string_bounded(
           writer, context, model->metadata.version, sizeof(model->metadata.version))) {
        return false;
    }
    JSON_LITERAL("},\"runtime\":{\"firmware_build\":");
    if(!write_json_string_bounded(
           writer, context, model->runtime.firmware_build, sizeof(model->runtime.firmware_build))) {
        return false;
    }
    JSON_LITERAL(",\"runtime_version\":");
    if(!write_json_string_bounded(
           writer, context, model->runtime.runtime_version, sizeof(model->runtime.runtime_version))) {
        return false;
    }
    JSON_LITERAL("},\"logs_dropped\":");
    if(!write_size(writer, context, model->logs_dropped)) return false;
    JSON_LITERAL(",\"logs\":[");
    for(size_t index = 0; index < model->log_count; ++index) {
        if(index > 0u) JSON_LITERAL(",");
        JSON_LITERAL("{\"level\":");
        if(!write_json_string(writer, context, diag_log_level_name(model->logs[index].level))) {
            return false;
        }
        JSON_LITERAL(",\"stage\":");
        if(!write_json_string(writer, context, diag_stage_name(model->logs[index].stage))) {
            return false;
        }
        JSON_LITERAL(",\"elapsed_ms\":");
        if(!write_unsigned(writer, context, model->logs[index].elapsed_ms)) return false;
        JSON_LITERAL(",\"message\":");
        if(!write_json_string_bounded(
               writer,
               context,
               model->logs[index].message,
               sizeof(model->logs[index].message))) {
            return false;
        }
        JSON_LITERAL("}");
    }
    JSON_LITERAL("]}");
#undef JSON_LITERAL
    return true;
}

bool diag_model_export_csv(const DiagModel* model, DiagWriter writer, void* context) {
    if(!writer || !model_export_valid(model)) return false;
    if(!write_literal(
           writer,
           context,
           "timestamp,provenance,recorded_provenance,run_succeeded,last_successful_stage,error_domain,error_code,"
           "protocol_candidates,protocols_confirmed,identity_protocol,identity_uid,identity_may_randomize,iso_a_uid,"
           "atqa,sak,cascade_count,cascade_evidence,product,version,firmware_build,"
           "runtime_version,log_count,logs_dropped,log_index,log_elapsed_ms,log_level,log_stage,"
           "log_message\n")) {
        return false;
    }
    if(!write_csv_string_bounded(writer, context, model->timestamp, sizeof(model->timestamp)) ||
       !write_literal(writer, context, ",") ||
       !write_csv_string_bounded(
           writer,
           context,
           diag_provenance_name(model->provenance),
           strlen(diag_provenance_name(model->provenance)) + 1u) ||
       !write_literal(writer, context, ",") ||
       !write_csv_string_bounded(
           writer,
           context,
           diag_provenance_name(model->recorded_provenance),
           strlen(diag_provenance_name(model->recorded_provenance)) + 1u) ||
       !write_literal(writer, context, model->run_succeeded ? ",true," : ",false,") ||
       !write_csv_string_bounded(
           writer,
           context,
           diag_stage_name(model->last_successful_stage),
           strlen(diag_stage_name(model->last_successful_stage)) + 1u) ||
       !write_literal(writer, context, ",")) {
        return false;
    }
    if(model->error.present) {
        if(!write_csv_string_bounded(
               writer, context, model->error.domain, sizeof(model->error.domain)) ||
           !write_literal(writer, context, ",") ||
           !write_signed(writer, context, model->error.code)) {
            return false;
        }
    } else if(!write_literal(writer, context, "\"\",")) {
        return false;
    }
    if(!write_literal(writer, context, ",") ||
       !write_protocols_csv(writer, context, model->protocol_candidates) ||
       !write_literal(writer, context, ",") ||
       !write_protocols_csv(writer, context, model->protocols_confirmed) ||
       !write_literal(writer, context, ",")) {
        return false;
    }
    if(model->identity.present) {
        const char* identity_protocol = diag_protocol_name(model->identity.protocol);
        if(!write_csv_string_bounded(
               writer, context, identity_protocol, strlen(identity_protocol) + 1u)) {
            return false;
        }
    } else if(!write_literal(writer, context, "\"\"")) {
        return false;
    }
    if(!write_literal(writer, context, ",\"")) return false;
    if(model->identity.present &&
       !write_hex(writer, context, model->identity.uid, model->identity.uid_size)) {
        return false;
    }
    if(!write_literal(writer, context, model->identity.may_randomize ? "\",true,\"" : "\",false,\"")) {
        return false;
    }
    if(model->iso_a.present &&
       !write_hex(writer, context, model->iso_a.uid, model->iso_a.uid_size)) {
        return false;
    }
    if(!write_literal(writer, context, "\",\"")) return false;
    if(model->iso_a.present &&
       !write_hex(writer, context, model->iso_a.atqa, sizeof(model->iso_a.atqa))) {
        return false;
    }
    if(!write_literal(writer, context, "\",")) return false;
    if(model->iso_a.present && !write_unsigned(writer, context, model->iso_a.sak)) return false;
    if(!write_literal(writer, context, ",")) return false;
    if(model->iso_a.present && !write_unsigned(writer, context, model->iso_a.cascade_count)) {
        return false;
    }
    if(!write_literal(writer, context, model->iso_a.present ? ",DERIVED," : ",,")) return false;
    if(!write_csv_string_bounded(
           writer, context, model->metadata.product, sizeof(model->metadata.product)) ||
       !write_literal(writer, context, ",") ||
       !write_csv_string_bounded(
           writer, context, model->metadata.version, sizeof(model->metadata.version)) ||
       !write_literal(writer, context, ",") ||
       !write_csv_string_bounded(
           writer, context, model->runtime.firmware_build, sizeof(model->runtime.firmware_build)) ||
       !write_literal(writer, context, ",") ||
       !write_csv_string_bounded(
           writer, context, model->runtime.runtime_version, sizeof(model->runtime.runtime_version)) ||
       !write_literal(writer, context, ",")) {
        return false;
    }
    if(!write_unsigned(writer, context, (unsigned)model->log_count) ||
       !write_literal(writer, context, ",") ||
       !write_size(writer, context, model->logs_dropped) ||
       !write_literal(writer, context, ",")) {
        return false;
    }
    if(model->log_count > 0u) {
        if(!write_csv_log_fields(&model->logs[0], 0u, writer, context)) return false;
    } else if(!write_literal(writer, context, ",,,,")) {
        return false;
    }
    if(!write_literal(writer, context, "\n")) return false;

    for(size_t index = 1u; index < model->log_count; ++index) {
        for(size_t column = 0u; column < 23u; ++column) {
            if(!write_literal(writer, context, ",")) return false;
        }
        if(!write_csv_log_fields(&model->logs[index], index, writer, context) ||
           !write_literal(writer, context, "\n")) {
            return false;
        }
    }
    return true;
}

#ifdef DIAG_MODEL_TESTING
bool diag_model_load_simulation(
    DiagModel* model,
    DiagSimulationCase simulation,
    size_t run_index) {
    if(!model || run_index >= DIAG_REPEATABILITY_RUNS) return false;
    diag_model_init(model, DiagProvenanceSimulation);

    const uint8_t uid[7] = {0x04, 0x25, 0x85, 0x93, 0x11, 0x22, 0x33};
    const uint8_t changed_uid[7] = {0x04, 0x25, 0x85, 0x93, 0x11, 0x22, 0x34};
    const uint8_t atqa[2] = {0x44, 0x00};
    char timestamp[DIAG_TIMESTAMP_CAPACITY];
    const int length = snprintf(
        timestamp, sizeof(timestamp), "2026-01-02T03:04:%02uZ", (unsigned)(5u + run_index));
    if(length <= 0 || (size_t)length >= sizeof(timestamp) ||
       !diag_model_set_timestamp(model, timestamp)) {
        return false;
    }
    if(!diag_model_set_runtime_provenance(model, "simulation-build", "simulation-1")) {
        return false;
    }
    if(!diag_model_add_protocol_candidate(model, DiagProtocolIso14443_3a)) return false;

    if(simulation == DiagSimulationCandidateOnly) {
        diag_model_mark_stage_success(model, DiagStageTechnologyDetected);
        return diag_model_add_log_at(
            model,
            DiagLogWarning,
            DiagStageTechnologyDetected,
            120u,
            "Candidate only; no API confirmation");
    }

    if(simulation != DiagSimulationStableIsoA &&
       simulation != DiagSimulationFailureIncluded) {
        return false;
    }
    if(simulation == DiagSimulationFailureIncluded && run_index == 2u) {
        diag_model_mark_stage_success(model, DiagStageTechnologyDetected);
        if(!diag_model_set_error(model, "nfc.poller", -7)) return false;
        return diag_model_add_log_at(
            model, DiagLogError, DiagStageIdentityRead, 245u, "Identity read failed");
    }

    const uint8_t* selected_uid =
        simulation == DiagSimulationFailureIncluded && run_index == 4u ? changed_uid : uid;
    if(!diag_model_set_identity(
           model, DiagProtocolIso14443_3a, selected_uid, sizeof(uid))) {
        return false;
    }
    if(!diag_model_set_iso_a_identity(model, selected_uid, sizeof(uid), atqa, 0x00u)) return false;
    if(!diag_model_set_product_metadata(model, "Simulated ISO A tag", "01")) return false;
    diag_model_mark_stage_success(model, DiagStageComplete);
    return diag_model_add_log_at(
        model, DiagLogSuccess, DiagStageComplete, 360u, "Simulated read complete");
}

bool diag_model_selftest(void) {
    if(strcmp(diag_protocol_name(DiagProtocolEmv), "EMV") != 0) return false;

    DiagModel* model = malloc(sizeof(*model));
    if(!model) return false;
    bool passed = false;
    DiagObservation observations[DIAG_REPEATABILITY_RUNS];
    for(size_t index = 0; index < DIAG_REPEATABILITY_RUNS; ++index) {
        if(!diag_model_load_simulation(model, DiagSimulationStableIsoA, index) ||
           !diag_model_observe(model, &observations[index])) {
            goto done;
        }
    }
    DiagRepeatability repeatability;
    if(!diag_observations_analyze(observations, &repeatability)) goto done;
    if(repeatability.successful_runs != DIAG_REPEATABILITY_RUNS ||
       !repeatability.identity_repeatable || !repeatability.protocols_repeatable ||
       !repeatability.metadata_repeatable || !repeatability.outcome_repeatable) {
        goto done;
    }

    diag_model_init(model, DiagProvenanceSaved);
    if(diag_model_confirm_protocol(model, DiagProtocolIso14443_3a, true)) goto done;
    passed = sizeof(DiagModel) < 10240u;

done:
    free(model);
    return passed;
}
#endif
