#include "../diag_model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) \
    do { \
        if(!(condition)) { \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return false; \
        } \
    } while(0)

typedef struct {
    char data[65536];
    size_t size;
    size_t calls;
    size_t fail_after_calls;
} Capture;

static bool capture_writer(const char* data, size_t size, void* context) {
    Capture* capture = context;
    if(capture->fail_after_calls != 0u && capture->calls >= capture->fail_after_calls) {
        return false;
    }
    ++capture->calls;
    if(size > sizeof(capture->data) - capture->size - 1u) return false;
    memcpy(&capture->data[capture->size], data, size);
    capture->size += size;
    capture->data[capture->size] = '\0';
    return true;
}

static bool file_writer(const char* data, size_t size, void* context) {
    return fwrite(data, 1u, size, context) == size;
}

static bool contains(const Capture* capture, const char* expected) {
    return strstr(capture->data, expected) != NULL;
}

static bool test_protocol_reference(void) {
    const char* expected[DIAG_PROTOCOL_COUNT] = {
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
    for(unsigned index = 0; index < DIAG_PROTOCOL_COUNT; ++index) {
        const DiagProtocolReference* reference = diag_protocol_reference((DiagProtocol)index);
        CHECK(reference != NULL);
        CHECK(reference->protocol == (DiagProtocol)index);
        CHECK(strcmp(reference->name, expected[index]) == 0);
        CHECK(strcmp(diag_protocol_name((DiagProtocol)index), expected[index]) == 0);
        CHECK(reference->family[0] != '\0');
        CHECK(reference->standard[0] != '\0');
        CHECK(reference->diagnostic_note[0] != '\0');
    }
    CHECK(diag_protocol_reference((DiagProtocol)DIAG_PROTOCOL_COUNT) == NULL);
    CHECK(strcmp(diag_protocol_name((DiagProtocol)99), "Invalid") == 0);
    return true;
}

static bool test_confirmation_provenance(void) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    CHECK(model.recorded_provenance == DiagProvenanceLive);
    CHECK(!diag_model_confirm_protocol(&model, DiagProtocolEmv, false));
    CHECK(model.protocols_confirmed == 0u);
    CHECK(diag_model_confirm_protocol(&model, DiagProtocolEmv, true));
    CHECK(model.protocols_confirmed == (UINT32_C(1) << DiagProtocolEmv));
    CHECK(model.protocol_candidates == model.protocols_confirmed);

    diag_model_init(&model, DiagProvenanceSaved);
    CHECK(model.recorded_provenance == DiagProvenanceSaved);
    CHECK(!diag_model_confirm_protocol(&model, DiagProtocolEmv, true));
    diag_model_init(&model, DiagProvenanceSimulation);
    CHECK(!diag_model_confirm_protocol(&model, DiagProtocolEmv, true));
    CHECK(!diag_model_confirm_protocol(&model, (DiagProtocol)99, true));
    return true;
}

static bool test_identity_and_metadata(void) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    const uint8_t uid4[4] = {1, 2, 3, 4};
    const uint8_t uid7[7] = {1, 2, 3, 4, 5, 6, 7};
    const uint8_t uid10[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    const uint8_t atqa[2] = {0x44, 0x00};
    CHECK(diag_model_set_iso_a_identity(&model, uid4, sizeof(uid4), atqa, 0x08));
    CHECK(model.iso_a.cascade_count == 1u);
    CHECK(diag_model_set_iso_a_identity(&model, uid7, sizeof(uid7), atqa, 0x00));
    CHECK(model.iso_a.cascade_count == 2u);
    CHECK(diag_model_set_iso_a_identity(&model, uid10, sizeof(uid10), atqa, 0x20));
    CHECK(model.iso_a.cascade_count == 3u);
    CHECK(!diag_model_set_iso_a_identity(&model, uid10, 5u, atqa, 0x20));
    CHECK(model.iso_a.uid_size == sizeof(uid10));

    CHECK(diag_model_set_identity(&model, DiagProtocolFelica, uid10, sizeof(uid10)));
    CHECK(model.identity.protocol == DiagProtocolFelica);
    CHECK(memcmp(model.identity.uid, uid10, sizeof(uid10)) == 0);
    CHECK(!diag_model_set_identity(&model, DiagProtocolFelica, uid10, 0u));
    CHECK(!diag_model_set_identity(&model, DiagProtocolFelica, uid10, 11u));
    uint8_t lf_uid[DIAG_MAX_UID_BYTES + 1u];
    for(size_t index = 0; index < sizeof(lf_uid); ++index) {
        lf_uid[index] = (uint8_t)(index + 1u);
    }
    CHECK(diag_model_set_identity(
        &model, DiagProtocolLfRfid, lf_uid, DIAG_MAX_UID_BYTES));
    CHECK(model.identity.uid_size == DIAG_MAX_UID_BYTES);
    CHECK(memcmp(model.identity.uid, lf_uid, DIAG_MAX_UID_BYTES) == 0);
    CHECK(!diag_model_set_identity(
        &model, DiagProtocolLfRfid, lf_uid, DIAG_MAX_UID_BYTES + 1u));
    const DiagProtocolReference* lf_reference =
        diag_protocol_reference(DiagProtocolLfRfid);
    CHECK(lf_reference != NULL);
    CHECK(strcmp(lf_reference->family, "LF RFID") == 0);
    CHECK(diag_model_set_product_metadata(&model, "EM4100", ""));
    CHECK(strcmp(model.metadata.product, "EM4100") == 0);
    const uint8_t random_uid[4] = {0x08, 2, 3, 4};
    CHECK(diag_model_set_identity(
        &model, DiagProtocolIso14443_3a, random_uid, sizeof(random_uid)));
    CHECK(model.identity.may_randomize);
    CHECK(diag_model_set_identity(&model, DiagProtocolIso14443_3b, uid4, sizeof(uid4)));
    CHECK(model.identity.may_randomize);
    CHECK(diag_model_set_identity(&model, DiagProtocolIso14443_3a, uid4, sizeof(uid4)));
    CHECK(!model.identity.may_randomize);

    CHECK(diag_model_set_product_metadata(&model, "NTAG 424 DNA", "0004040502020013"));
    CHECK(diag_model_set_runtime_provenance(&model, "momentum-dev-deadbeef", "0.1.0"));
    char too_long[DIAG_PRODUCT_CAPACITY + 1u];
    memset(too_long, 'x', sizeof(too_long) - 1u);
    too_long[sizeof(too_long) - 1u] = '\0';
    CHECK(!diag_model_set_product_metadata(&model, too_long, "changed"));
    CHECK(strcmp(model.metadata.product, "NTAG 424 DNA") == 0);
    CHECK(strcmp(model.metadata.version, "0004040502020013") == 0);
    return true;
}

static bool test_logs_and_errors(void) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_model_set_timestamp(&model, "2026-10-15T18:20:30Z"));
    diag_model_mark_stage_success(&model, DiagStageIdentityRead);
    CHECK(model.last_successful_stage == DiagStageIdentityRead);
    CHECK(diag_model_set_error(&model, "nfc.poller.iso_a", -123456));
    CHECK(model.error.present);
    CHECK(model.error.code == -123456);
    CHECK(strcmp(model.error.domain, "nfc.poller.iso_a") == 0);
    CHECK(!model.run_succeeded);
    diag_model_clear_error(&model);
    CHECK(!model.error.present);

    for(size_t index = 0; index < DIAG_MAX_LOGS; ++index) {
        CHECK(diag_model_add_log_at(
            &model, DiagLogInfo, DiagStageFieldStarted, (uint32_t)(index * 10u), "event"));
    }
    CHECK(model.log_count == DIAG_MAX_LOGS);
    CHECK(model.logs[63].elapsed_ms == 630u);
    CHECK(diag_model_add_log_at(
        &model, DiagLogError, DiagStageProtocolRead, 999u, "newest error"));
    CHECK(model.log_count == DIAG_MAX_LOGS);
    CHECK(model.logs_dropped == 1u);
    CHECK(model.logs[63].elapsed_ms == 999u);
    CHECK(strcmp(model.logs[63].message, "newest error") == 0);

    diag_model_init(&model, DiagProvenanceLive);
    char too_long[DIAG_LOG_MESSAGE_CAPACITY + 1u];
    memset(too_long, 'z', sizeof(too_long) - 1u);
    too_long[sizeof(too_long) - 1u] = '\0';
    CHECK(!diag_model_add_log(&model, DiagLogInfo, DiagStageNone, too_long));
    CHECK(model.log_count == 0u);
    model.log_count = DIAG_MAX_LOGS + 1u;
    CHECK(!diag_model_add_log(&model, DiagLogInfo, DiagStageNone, "corrupt"));
    return true;
}

static bool test_compare_and_repeatability(void) {
    DiagModel left;
    DiagModel right;
    diag_model_init(&left, DiagProvenanceLive);
    diag_model_init(&right, DiagProvenanceLive);
    DiagComparison comparison = diag_model_compare(&left, &right);
    CHECK(!comparison.identity_same);
    CHECK(!comparison.metadata_same);

    CHECK(diag_model_load_simulation(&left, DiagSimulationStableIsoA, 0u));
    CHECK(diag_model_load_simulation(&right, DiagSimulationStableIsoA, 1u));
    comparison = diag_model_compare(&left, &right);
    CHECK(comparison.identity_same);
    CHECK(comparison.protocols_same);
    CHECK(comparison.metadata_same);
    CHECK(comparison.outcome_same);
    right.iso_a.atqa[0] ^= 1u;
    comparison = diag_model_compare(&left, &right);
    CHECK(!comparison.metadata_same);
    CHECK(comparison.identity_same);

    DiagObservation observations[DIAG_REPEATABILITY_RUNS];
    DiagModel scratch;
    for(size_t index = 0; index < DIAG_REPEATABILITY_RUNS; ++index) {
        CHECK(diag_model_load_simulation(&scratch, DiagSimulationStableIsoA, index));
        CHECK(diag_model_observe(&scratch, &observations[index]));
    }
    DiagRepeatability result;
    CHECK(diag_observations_analyze(observations, &result));
    CHECK(result.run_count == 5u);
    CHECK(result.successful_runs == 5u);
    CHECK(result.failed_runs == 0u);
    CHECK(result.identity_repeatable);
    CHECK(result.protocols_repeatable);
    CHECK(result.metadata_repeatable);
    CHECK(result.outcome_repeatable);

    for(size_t index = 0; index < DIAG_REPEATABILITY_RUNS; ++index) {
        CHECK(diag_model_load_simulation(&scratch, DiagSimulationFailureIncluded, index));
        CHECK(diag_model_observe(&scratch, &observations[index]));
    }
    CHECK(diag_observations_analyze(observations, &result));
    CHECK(result.successful_runs == 4u);
    CHECK(result.failed_runs == 1u);
    CHECK(result.identity_observed_runs == 4u);
    CHECK(!result.identity_repeatable);
    CHECK(!result.protocols_repeatable || result.protocol_observed_runs == 5u);
    CHECK(!result.metadata_repeatable);
    CHECK(!result.outcome_repeatable);
    return true;
}

static bool test_exports(void) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    const uint8_t uid[4] = {0x08, 0xAD, 0xBE, 0xEF};
    const uint8_t atqa[2] = {0x04, 0x00};
    CHECK(diag_model_set_timestamp(&model, "2026-10-15T18:20:30Z"));
    CHECK(diag_model_set_identity(&model, DiagProtocolIso14443_3a, uid, sizeof(uid)));
    CHECK(diag_model_set_iso_a_identity(&model, uid, sizeof(uid), atqa, 0x08));
    CHECK(diag_model_add_protocol_candidate(&model, DiagProtocolIso14443_3a));
    CHECK(diag_model_confirm_protocol(&model, DiagProtocolMfClassic, true));
    CHECK(diag_model_set_product_metadata(&model, "Classic \"1K\"", "v1,rev2"));
    CHECK(diag_model_set_runtime_provenance(&model, "build-123", "runtime-456"));
    CHECK(diag_model_add_log_at(
        &model, DiagLogWarning, DiagStageProtocolRead, 42u, "quote \" slash \\ line\nctrl\x01"));
    diag_model_mark_stage_success(&model, DiagStageComplete);

    Capture json = {0};
    CHECK(diag_model_export_json(&model, capture_writer, &json));
    CHECK(json.calls > 10u);
    CHECK(contains(&json, "\"provenance\":\"Live\""));
    CHECK(contains(&json, "\"uid\":\"08ADBEEF\""));
    CHECK(contains(&json, "\"may_randomize\":true"));
    CHECK(contains(&json, "\"cascade_count\":{\"value\":1,\"evidence\":\"DERIVED\"}"));
    CHECK(contains(&json, "\"elapsed_ms\":42"));
    CHECK(contains(&json, "\"logs_dropped\":0"));
    CHECK(contains(&json, "quote \\\" slash \\\\ line\\nctrl\\u0001"));
    CHECK(contains(&json, "\"firmware_build\":\"build-123\""));

    Capture csv = {0};
    CHECK(diag_model_export_csv(&model, capture_writer, &csv));
    CHECK(contains(&csv, "identity_protocol,identity_uid,identity_may_randomize,iso_a_uid"));
    CHECK(contains(&csv, "log_index,log_elapsed_ms,log_level,log_stage,log_message"));
    CHECK(contains(&csv, "\"Classic \"\"1K\"\"\""));
    CHECK(contains(&csv, "quote \"\" slash"));
    CHECK(contains(&csv, "\"08ADBEEF\",true"));
    CHECK(contains(&csv, ",1,DERIVED,"));

    Capture failing = {.fail_after_calls = 2u};
    CHECK(!diag_model_export_json(&model, capture_writer, &failing));

    memset(model.timestamp, 'x', sizeof(model.timestamp));
    Capture invalid = {0};
    CHECK(!diag_model_export_json(&model, capture_writer, &invalid));
    CHECK(!diag_model_export_csv(&model, capture_writer, &invalid));
    CHECK(invalid.size == 0u);
    model.timestamp[0] = '\0';
    model.protocol_candidates = UINT32_C(1) << DIAG_PROTOCOL_COUNT;
    CHECK(!diag_model_export_json(&model, capture_writer, &invalid));
    CHECK(!diag_model_export_csv(&model, capture_writer, &invalid));
    model.protocol_candidates = 0u;
    model.protocols_confirmed = 0u;
    model.logs[0].level = (DiagLogLevel)-1;
    CHECK(!diag_model_export_json(&model, capture_writer, &invalid));
    CHECK(!diag_model_export_csv(&model, capture_writer, &invalid));
    CHECK(invalid.size == 0u);
    return true;
}

static bool test_simulation_and_advice(void) {
    DiagModel model;
    CHECK(diag_model_load_simulation(&model, DiagSimulationCandidateOnly, 4u));
    CHECK(model.provenance == DiagProvenanceSimulation);
    CHECK(model.recorded_provenance == DiagProvenanceSimulation);
    CHECK(model.protocol_candidates != 0u);
    CHECK(model.protocols_confirmed == 0u);
    CHECK(model.logs[0].elapsed_ms == 120u);
    CHECK(strstr(diag_stage_advice(DiagStageIdentityRead), "error domain and code") != NULL);
    CHECK(sizeof(DiagModel) < 10240u);
    CHECK(diag_model_selftest());
    return true;
}

static bool write_parser_fixtures(const char* json_path, const char* csv_path) {
    DiagModel model;
    CHECK(diag_model_load_simulation(&model, DiagSimulationStableIsoA, 0u));
    CHECK(diag_model_set_product_metadata(&model, "quoted \"product\"", "line\nversion"));
    CHECK(diag_model_add_log_at(
        &model, DiagLogWarning, DiagStageMetadataRead, 500u, "comma, quote \" and newline\n"));

    FILE* json = fopen(json_path, "wb");
    CHECK(json != NULL);
    const bool json_ok = diag_model_export_json(&model, file_writer, json);
    const bool json_close_ok = fclose(json) == 0;
    CHECK(json_ok && json_close_ok);

    FILE* csv = fopen(csv_path, "wb");
    CHECK(csv != NULL);
    const bool csv_ok = diag_model_export_csv(&model, file_writer, csv);
    const bool csv_close_ok = fclose(csv) == 0;
    CHECK(csv_ok && csv_close_ok);
    return true;
}

int main(int argc, char** argv) {
    if(!test_protocol_reference() || !test_confirmation_provenance() ||
       !test_identity_and_metadata() || !test_logs_and_errors() ||
       !test_compare_and_repeatability() || !test_exports() ||
       !test_simulation_and_advice()) {
        return EXIT_FAILURE;
    }
    if(argc == 3 && !write_parser_fixtures(argv[1], argv[2])) return EXIT_FAILURE;
    if(argc != 1 && argc != 3) return EXIT_FAILURE;
    puts("diag_model tests passed");
    return EXIT_SUCCESS;
}
