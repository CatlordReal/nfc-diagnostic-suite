#include "../diag_lf.h"

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

#define LF_BIT (UINT32_C(1) << (unsigned)DiagProtocolLfRfid)

static bool test_native_decode_gate(void) {
    const uint8_t data[] = {0x12, 0x34, 0x56, 0x78, 0x9a};
    DiagModel model;
    DiagLfStats stats = {.mode = DiagLfModeCard};
    diag_model_init(&model, DiagProvenanceLive);

    CHECK(!diag_lf_test_decode(
        &model, &stats, "EM4100", data, sizeof(data), false));
    CHECK(!model.identity.present);
    CHECK(model.protocols_confirmed == 0u);
    CHECK(!stats.decoded);

    CHECK(diag_lf_test_decode(
        &model, &stats, "EM4100", data, sizeof(data), true));
    CHECK(stats.decoded);
    CHECK(model.identity.present);
    CHECK(model.identity.protocol == DiagProtocolLfRfid);
    CHECK(model.identity.uid_size == sizeof(data));
    CHECK(memcmp(model.identity.uid, data, sizeof(data)) == 0);
    CHECK(strcmp(model.metadata.product, "EM4100") == 0);
    CHECK(strcmp(model.metadata.version, "Native LFRFIDWorker decoded data") == 0);
    CHECK((model.protocol_candidates & LF_BIT) != 0u);
    CHECK((model.protocols_confirmed & LF_BIT) != 0u);
    CHECK(model.last_successful_stage == DiagStageMetadataRead);
    return true;
}

static bool test_decode_bounds_and_provenance(void) {
    uint8_t data[DIAG_MAX_UID_BYTES + 1u];
    for(size_t index = 0; index < sizeof(data); ++index) data[index] = (uint8_t)index;
    DiagModel model;
    DiagLfStats stats = {.mode = DiagLfModeCard};

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(!diag_lf_test_decode(&model, &stats, "HID", data, 0u, true));
    CHECK(!diag_lf_test_decode(&model, &stats, "HID", data, sizeof(data), true));
    CHECK(!model.identity.present);
    CHECK(model.protocols_confirmed == 0u);

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_lf_test_decode(
        &model, &stats, "HID Generic", data, DIAG_MAX_UID_BYTES, true));
    CHECK(model.identity.uid_size == DIAG_MAX_UID_BYTES);
    CHECK(memcmp(model.identity.uid, data, DIAG_MAX_UID_BYTES) == 0);

    char oversized_name[DIAG_PRODUCT_CAPACITY + 1u];
    memset(oversized_name, 'x', sizeof(oversized_name));
    oversized_name[sizeof(oversized_name) - 1u] = '\0';
    diag_model_init(&model, DiagProvenanceLive);
    memset(&stats, 0, sizeof(stats));
    stats.mode = DiagLfModeCard;
    CHECK(!diag_lf_test_decode(&model, &stats, oversized_name, data, 1u, true));
    CHECK(!model.identity.present);

    diag_model_init(&model, DiagProvenanceSaved);
    CHECK(!diag_lf_test_decode(&model, &stats, "EM4100", data, 1u, true));
    CHECK(!model.identity.present);
    CHECK(model.protocols_confirmed == 0u);
    return true;
}

static bool test_lf_field_samples(void) {
    DiagLfStats stats = {
        .mode = DiagLfModeReader,
        .sample_period_ms = DIAG_LF_FIELD_SAMPLE_MS,
    };
    CHECK(diag_lf_test_sample(&stats, false, 70000u, false, false));
    CHECK(diag_lf_test_sample(&stats, true, 124800u, false, false));
    CHECK(diag_lf_test_sample(&stats, true, 126200u, false, false));
    CHECK(diag_lf_test_sample(&stats, false, 0u, false, false));
    CHECK(stats.samples_total == 4u);
    CHECK(stats.field_present_samples == 2u);
    CHECK(stats.field_absent_samples == 2u);
    CHECK(stats.field_seen);
    CHECK(stats.frequency_hz_min == 124800u);
    CHECK(stats.frequency_hz_max == 126200u);
    CHECK(stats.frequency_hz_last == 0u);
    CHECK(stats.nfc_field_present_samples == 0u);
    CHECK(stats.nfc_field_absent_samples == 0u);
    return true;
}

static bool test_both_band_samples_no_protocol_claim(void) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    DiagLfStats stats = {
        .mode = DiagLfModeReaderBoth,
        .sample_period_ms = DIAG_LF_FIELD_SAMPLE_MS,
    };
    CHECK(diag_lf_test_sample(&stats, false, 1010u, true, true));
    CHECK(diag_lf_test_sample(&stats, true, 125000u, true, false));
    CHECK(stats.samples_total == 2u);
    CHECK(stats.nfc_field_present_samples == 1u);
    CHECK(stats.nfc_field_absent_samples == 1u);
    CHECK(stats.nfc_field_seen);
    CHECK(stats.field_seen);
    CHECK(model.protocol_candidates == 0u);
    CHECK(model.protocols_confirmed == 0u);
    CHECK(!model.identity.present);

    DiagLfStats card = {.mode = DiagLfModeCard};
    CHECK(!diag_lf_test_sample(&card, true, 125000u, true, true));
    CHECK(card.samples_total == 0u);
    DiagLfStats lf_only = {.mode = DiagLfModeReader};
    CHECK(!diag_lf_test_sample(&lf_only, true, 125000u, true, true));
    CHECK(lf_only.samples_total == 0u);
    return true;
}

static bool test_finish_outcomes(void) {
    DiagModel model;
    DiagLfStats stats = {.mode = DiagLfModeCard};
    diag_model_init(&model, DiagProvenanceLive);
    diag_model_mark_stage_success(&model, DiagStageFieldStarted);
    diag_lf_test_finish(&model, &stats, false, true);
    CHECK(stats.timed_out);
    CHECK(model.error.present);
    CHECK(strcmp(model.error.domain, "app.lf_deadline") == 0);
    CHECK(model.error.code == 1);
    CHECK(model.last_successful_stage == DiagStageFieldStarted);
    CHECK(!model.run_succeeded);

    memset(&stats, 0, sizeof(stats));
    stats.mode = DiagLfModeReader;
    diag_model_init(&model, DiagProvenanceLive);
    diag_model_mark_stage_success(&model, DiagStageFieldStarted);
    diag_lf_test_finish(&model, &stats, false, true);
    CHECK(stats.timed_out);
    CHECK(!model.error.present);
    CHECK(model.run_succeeded);
    CHECK(model.last_successful_stage == DiagStageComplete);
    CHECK(model.protocols_confirmed == 0u);

    memset(&stats, 0, sizeof(stats));
    stats.mode = DiagLfModeReaderBoth;
    diag_model_init(&model, DiagProvenanceLive);
    diag_model_mark_stage_success(&model, DiagStageFieldStarted);
    diag_lf_test_finish(&model, &stats, true, false);
    CHECK(stats.cancelled);
    CHECK(!stats.timed_out);
    CHECK(model.error.present);
    CHECK(strcmp(model.error.domain, "app.cancelled") == 0);
    CHECK(model.error.code == 2);
    CHECK(model.last_successful_stage == DiagStageFieldStarted);
    CHECK(!model.run_succeeded);
    return true;
}

int main(void) {
    if(!test_native_decode_gate() || !test_decode_bounds_and_provenance() ||
       !test_lf_field_samples() || !test_both_band_samples_no_protocol_claim() ||
       !test_finish_outcomes()) {
        return EXIT_FAILURE;
    }
    puts("diag_lf evidence tests passed");
    return EXIT_SUCCESS;
}
