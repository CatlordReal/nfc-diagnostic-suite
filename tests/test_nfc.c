#include "../diag_nfc.h"

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

#define BIT(protocol) (UINT32_C(1) << (unsigned)(protocol))

static bool test_iso_a_uid_sizes(void) {
    const uint8_t atqa[2] = {0x44, 0x00};
    const uint8_t uid4[4] = {1, 2, 3, 4};
    const uint8_t uid7[7] = {1, 2, 3, 4, 5, 6, 7};
    const uint8_t uid10[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    DiagModel model;

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_nfc_test_identity_a(&model, uid4, sizeof(uid4), atqa, 0x00));
    CHECK(model.iso_a.cascade_count == 1u);
    CHECK(model.protocols_confirmed == BIT(DiagProtocolIso14443_3a));

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_nfc_test_identity_a(&model, uid7, sizeof(uid7), atqa, 0x00));
    CHECK(model.iso_a.cascade_count == 2u);

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_nfc_test_identity_a(&model, uid10, sizeof(uid10), atqa, 0x20));
    CHECK(model.iso_a.cascade_count == 3u);

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(!diag_nfc_test_identity_a(&model, uid10, 5u, atqa, 0x00));
    CHECK(model.protocol_candidates == 0u);
    CHECK(model.protocols_confirmed == 0u);
    CHECK(!model.identity.present);
    return true;
}

static bool test_sak_hints_are_candidates(void) {
    const uint8_t atqa[2] = {0x44, 0x00};
    const uint8_t uid4[4] = {1, 2, 3, 4};
    const uint8_t uid7[7] = {1, 2, 3, 4, 5, 6, 7};
    DiagModel model;

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_nfc_test_identity_a(&model, uid4, sizeof(uid4), atqa, 0x20));
    CHECK(model.protocol_candidates & BIT(DiagProtocolIso14443_4a));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolIso14443_4a)));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfPlus)));

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_nfc_test_identity_a(&model, uid4, sizeof(uid4), atqa, 0x08));
    CHECK(model.protocol_candidates & BIT(DiagProtocolMfClassic));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfClassic)));

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_nfc_test_identity_a(&model, uid7, sizeof(uid7), atqa, 0x00));
    CHECK(model.protocol_candidates & BIT(DiagProtocolMfUltralight));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfUltralight)));
    return true;
}

static bool test_classic_nonce_exact_evidence(void) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    CHECK(!diag_nfc_test_classic_nonce(&model, 0, 4u));
    CHECK(!diag_nfc_test_classic_nonce(&model, 6, 3u));
    CHECK(!diag_nfc_test_classic_nonce(&model, 6, 5u));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfClassic)));
    CHECK(diag_nfc_test_classic_nonce(&model, 6, 4u));
    CHECK(model.protocols_confirmed & BIT(DiagProtocolMfClassic));
    return true;
}

static bool test_ultralight_version_validation(void) {
    const uint8_t uid[7] = {0x04, 1, 2, 3, 4, 5, 6};
    const uint8_t valid[8] = {0x00, 0x04, 0x03, 0x01, 0x01, 0x00, 0x0f, 0x03};
    uint8_t invalid[8];
    DiagModel model;

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_model_set_identity(&model, DiagProtocolIso14443_3a, uid, sizeof(uid)));
    CHECK(diag_nfc_test_version(
        &model, DiagProtocolMfUltralight, 0, valid, sizeof(valid), uid, sizeof(uid)));
    CHECK(model.protocols_confirmed & BIT(DiagProtocolMfUltralight));

    memcpy(invalid, valid, sizeof(invalid));
    invalid[1] = 0x05;
    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_model_set_identity(&model, DiagProtocolIso14443_3a, uid, sizeof(uid)));
    CHECK(!diag_nfc_test_version(
        &model, DiagProtocolMfUltralight, 0, invalid, sizeof(invalid), uid, sizeof(uid)));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfUltralight)));

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_model_set_identity(&model, DiagProtocolIso14443_3a, uid, sizeof(uid)));
    CHECK(!diag_nfc_test_version(
        &model, DiagProtocolMfUltralight, -9, valid, sizeof(valid), uid, sizeof(uid)));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfUltralight)));
    CHECK(model.logs[0].stage == DiagStageMetadataRead);
    return true;
}

static bool test_plus_requires_direct_version(void) {
    const uint8_t atqa[2] = {0x44, 0x00};
    const uint8_t uid[7] = {0x04, 1, 2, 3, 4, 5, 6};
    uint8_t version[28] = {0};
    version[0] = 0x04;
    version[1] = 0x02;
    memcpy(version + 14, uid, sizeof(uid));

    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_nfc_test_identity_a(&model, uid, sizeof(uid), atqa, 0x20));
    CHECK(!(model.protocol_candidates & BIT(DiagProtocolMfPlus)));
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfPlus)));
    CHECK(diag_nfc_test_version(
        &model, DiagProtocolMfPlus, 0, version, sizeof(version), NULL, 0u));
    CHECK(model.protocols_confirmed & BIT(DiagProtocolMfPlus));
    return true;
}

static bool test_swapped_and_randomized_uid(void) {
    const uint8_t stable_uid[7] = {0x04, 1, 2, 3, 4, 5, 6};
    const uint8_t other_uid[7] = {0x04, 6, 5, 4, 3, 2, 1};
    const uint8_t random_uid[4] = {0x08, 0xaa, 0xbb, 0xcc};
    uint8_t version[28] = {0};
    version[0] = 0x04;
    version[1] = 0x01;
    memcpy(version + 14, other_uid, sizeof(other_uid));
    DiagModel model;

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_model_set_identity(
        &model, DiagProtocolIso14443_3a, stable_uid, sizeof(stable_uid)));
    diag_model_mark_stage_success(&model, DiagStageIdentityRead);
    CHECK(!diag_nfc_test_version(
        &model, DiagProtocolMfDesfire, 0, version, sizeof(version), NULL, 0u));
    CHECK(model.error.present);
    CHECK(strcmp(model.error.domain, "app.identity") == 0);
    CHECK(model.error.code == 3);
    CHECK(model.last_successful_stage == DiagStageIdentityRead);
    CHECK(!(model.protocols_confirmed & BIT(DiagProtocolMfDesfire)));

    diag_model_init(&model, DiagProvenanceLive);
    CHECK(diag_model_set_identity(
        &model, DiagProtocolIso14443_3a, random_uid, sizeof(random_uid)));
    CHECK(model.identity.may_randomize);
    CHECK(diag_nfc_test_version(
        &model, DiagProtocolMfDesfire, 0, version, sizeof(version), NULL, 0u));
    CHECK(model.protocols_confirmed & BIT(DiagProtocolMfDesfire));
    CHECK(model.last_successful_stage == DiagStageMetadataRead);
    CHECK(model.log_count == 1u);
    CHECK(strstr(model.logs[0].message, "correlation unavailable") != NULL);
    return true;
}

static bool test_failure_preserves_stage(void) {
    struct {
        bool cancelled;
        bool discovery;
        const char* domain;
        int32_t code;
    } cases[] = {
        {true, false, "app.cancelled", 2},
        {false, true, "app.discovery_deadline", 1},
        {false, false, "app.stage_deadline", 1},
    };
    for(size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        DiagModel model;
        diag_model_init(&model, DiagProvenanceLive);
        diag_model_mark_stage_success(&model, DiagStageIdentityRead);
        diag_nfc_test_finish_failure(&model, cases[index].cancelled, cases[index].discovery);
        CHECK(!model.run_succeeded);
        CHECK(model.error.present);
        CHECK(strcmp(model.error.domain, cases[index].domain) == 0);
        CHECK(model.error.code == cases[index].code);
        CHECK(model.last_successful_stage == DiagStageIdentityRead);
    }
    return true;
}

static bool test_bounded_base_discovery(void) {
    static const DiagProtocol expected[] = {
        DiagProtocolIso14443_3a,
        DiagProtocolIso14443_3b,
        DiagProtocolIso15693_3,
        DiagProtocolFelica,
        DiagProtocolSt25tb,
    };
    for(size_t index = 0; index < sizeof(expected) / sizeof(expected[0]); ++index) {
        DiagProtocol protocol = DiagProtocolEmv;
        CHECK(diag_nfc_test_base_protocol(index, &protocol));
        CHECK(protocol == expected[index]);
    }
    DiagProtocol protocol = DiagProtocolEmv;
    CHECK(!diag_nfc_test_base_protocol(sizeof(expected) / sizeof(expected[0]), &protocol));
    CHECK(protocol == DiagProtocolEmv);
    CHECK(!diag_nfc_test_base_protocol(0, NULL));

    const uint8_t slix[8] = {0xe0, 0x04, 0x01, 0x08, 0, 0, 0, 0};
    const uint8_t slix2[8] = {0xe0, 0x04, 0x01, 0x10, 0, 0, 0, 0};
    const uint8_t slix_s[8] = {0xe0, 0x04, 0x02, 0x00, 0, 0, 0, 0};
    const uint8_t slix_l[8] = {0xe0, 0x04, 0x03, 0x00, 0, 0, 0, 0};
    const uint8_t other[8] = {0xe0, 0x02, 0x01, 0x08, 0, 0, 0, 0};
    CHECK(diag_nfc_test_v_candidates(slix, sizeof(slix)) == BIT(DiagProtocolSlix));
    CHECK(diag_nfc_test_v_candidates(slix2, sizeof(slix2)) == BIT(DiagProtocolSlix));
    CHECK(diag_nfc_test_v_candidates(slix_s, sizeof(slix_s)) == BIT(DiagProtocolSlix));
    CHECK(diag_nfc_test_v_candidates(slix_l, sizeof(slix_l)) == BIT(DiagProtocolSlix));
    CHECK(diag_nfc_test_v_candidates(other, sizeof(other)) == 0);
    CHECK(diag_nfc_test_v_candidates(slix, sizeof(slix) - 1u) == 0);
    CHECK(diag_nfc_test_v_candidates(NULL, sizeof(slix)) == 0);
    return true;
}

int main(void) {
    if(!test_iso_a_uid_sizes() || !test_sak_hints_are_candidates() ||
       !test_classic_nonce_exact_evidence() || !test_ultralight_version_validation() ||
       !test_plus_requires_direct_version() || !test_swapped_and_randomized_uid() ||
       !test_failure_preserves_stage() || !test_bounded_base_discovery()) {
        return EXIT_FAILURE;
    }
    puts("diag_nfc evidence tests passed");
    return EXIT_SUCCESS;
}
