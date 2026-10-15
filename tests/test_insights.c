#include "../diag_insights.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static DiagIsoAIdentity stimulus(uint8_t last) {
    DiagIsoAIdentity identity = {
        .present = true,
        .uid = {0x04, 0x11, 0x22, 0x33, 0x44, 0x55, last},
        .uid_size = 7u,
        .atqa = {0x44, 0x00},
        .sak = 0x00,
        .cascade_count = 2u,
    };
    return identity;
}

static DiagReaderStats type_a_stats(uint32_t elapsed_ms) {
    DiagReaderStats stats = {
        .mode = DiagReaderModeTypeA,
        .field_available = true,
        .selection_available = true,
        .rx_total_available = true,
        .elapsed_ms = elapsed_ms,
        .field_on_count = elapsed_ms / 5000u,
        .field_off_count = elapsed_ms / 10000u,
        .field_on_ms = elapsed_ms * 2u / 3u,
        .field_off_ms = elapsed_ms / 3u,
        .selection_count = elapsed_ms / 7500u,
        .request_count = elapsed_ms / 1500u,
        .auth_request_count = elapsed_ms / 7500u,
        .error_count = elapsed_ms / 30000u,
        .min_request_gap_ms = 400u,
        .max_request_gap_ms = 2000u,
    };
    return stats;
}

static void test_reader_similarity_and_context(void) {
    DiagIsoAIdentity first_stimulus = stimulus(0x66);
    DiagReaderStats first_stats = type_a_stats(30000u);
    DiagReaderStats second_stats = type_a_stats(15000u);
    second_stats.min_request_gap_ms = 420u;
    second_stats.max_request_gap_ms = 2100u;
    DiagReaderFingerprint first;
    DiagReaderFingerprint second;
    assert(diag_reader_fingerprint_from_reader(&first_stats, &first_stimulus, &first));
    assert(diag_reader_fingerprint_from_reader(&second_stats, &first_stimulus, &second));
    DiagReaderFingerprintMatch match = diag_reader_fingerprint_compare(&first, &second);
    assert(match.result == DiagReaderFingerprintSimilar);
    assert(match.score >= 70u);
    assert(strstr(match.reason, "identity not proven"));

    DiagReaderStats different_stats = type_a_stats(30000u);
    different_stats.selection_count = 1u;
    different_stats.request_count = 10u;
    different_stats.auth_request_count = 0u;
    different_stats.min_request_gap_ms = 4000u;
    different_stats.max_request_gap_ms = 12000u;
    DiagReaderFingerprint different;
    assert(diag_reader_fingerprint_from_reader(
        &different_stats, &first_stimulus, &different));
    match = diag_reader_fingerprint_compare(&first, &different);
    assert(match.result == DiagReaderFingerprintDifferent);

    DiagIsoAIdentity other_stimulus = stimulus(0x67);
    assert(diag_reader_fingerprint_from_reader(&second_stats, &other_stimulus, &second));
    match = diag_reader_fingerprint_compare(&first, &second);
    assert(match.result == DiagReaderFingerprintNotComparable);
    assert(strstr(match.reason, "Stimulus"));

    assert(diag_reader_fingerprint_from_reader(&second_stats, NULL, &second));
    match = diag_reader_fingerprint_compare(&first, &second);
    assert(match.result == DiagReaderFingerprintInsufficient);
}

static void test_low_evidence_and_zero_denominators(void) {
    DiagReaderStats passive = {
        .mode = DiagReaderModeField,
        .field_available = true,
        .elapsed_ms = 30000u,
        .sample_period_ms = 10u,
        .samples = 3000u,
        .field_observed = true,
        .field_on_count = 1u,
    };
    DiagReaderFingerprint first;
    DiagReaderFingerprint second;
    assert(diag_reader_fingerprint_from_reader(&passive, NULL, &first));
    assert(first.field_duty_permille == 0u);
    assert(diag_reader_fingerprint_from_reader(&passive, NULL, &second));
    assert(diag_reader_fingerprint_compare(&first, &second).result ==
           DiagReaderFingerprintInsufficient);

    passive.field_off_count = 1u;
    passive.field_on_ms = 15000u;
    passive.field_off_ms = 15000u;
    assert(diag_reader_fingerprint_from_reader(&passive, NULL, &first));
    assert(diag_reader_fingerprint_from_reader(&passive, NULL, &second));
    assert(diag_reader_fingerprint_compare(&first, &second).result ==
           DiagReaderFingerprintSimilar);

    DiagReaderStats active = type_a_stats(30000u);
    DiagIsoAIdentity identity = stimulus(0x66);
    assert(diag_reader_fingerprint_from_reader(&active, &identity, &first));
    assert(diag_reader_fingerprint_compare(&first, &second).result ==
           DiagReaderFingerprintNotComparable);
}

static DiagLfStats lf_stats(uint32_t min_hz, uint32_t max_hz) {
    DiagLfStats stats = {
        .mode = DiagLfModeReaderBoth,
        .elapsed_ms = 25000u,
        .sample_period_ms = 100u,
        .samples_total = 250u,
        .field_present_samples = 180u,
        .field_absent_samples = 70u,
        .frequency_hz_min = min_hz,
        .frequency_hz_max = max_hz,
        .frequency_hz_last = (min_hz + max_hz) / 2u,
        .nfc_field_present_samples = 50u,
        .nfc_field_absent_samples = 200u,
        .field_seen = true,
        .nfc_field_seen = true,
    };
    return stats;
}

static void test_lf_frequency_heuristic(void) {
    DiagLfStats first_stats = lf_stats(124800u, 126200u);
    DiagLfStats close_stats = lf_stats(124900u, 126400u);
    DiagLfStats far_stats = lf_stats(133500u, 135000u);
    DiagReaderFingerprint first;
    DiagReaderFingerprint close;
    DiagReaderFingerprint far;
    assert(diag_reader_fingerprint_from_fields(&first_stats, &first));
    assert(diag_reader_fingerprint_from_fields(&close_stats, &close));
    assert(diag_reader_fingerprint_from_fields(&far_stats, &far));
    assert(diag_reader_fingerprint_compare(&first, &close).result ==
           DiagReaderFingerprintSimilar);
    assert(diag_reader_fingerprint_compare(&first, &far).result ==
           DiagReaderFingerprintDifferent);

    DiagLfStats no_frequency = first_stats;
    no_frequency.frequency_hz_min = 0u;
    no_frequency.frequency_hz_max = 0u;
    no_frequency.frequency_hz_last = 0u;
    assert(diag_reader_fingerprint_from_fields(&no_frequency, &close));
    assert(diag_reader_fingerprint_compare(&first, &close).result ==
           DiagReaderFingerprintInsufficient);

    DiagLfStats other_mode = first_stats;
    other_mode.mode = DiagLfModeReader;
    other_mode.nfc_field_present_samples = 0u;
    other_mode.nfc_field_absent_samples = 0u;
    assert(diag_reader_fingerprint_from_fields(&other_mode, &close));
    assert(diag_reader_fingerprint_compare(&first, &close).result ==
           DiagReaderFingerprintNotComparable);

    first_stats.mode = DiagLfModeCard;
    assert(!diag_reader_fingerprint_from_fields(&first_stats, &first));
}

static uint32_t test_crc32(const uint8_t* data, size_t size) {
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for(size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for(unsigned bit = 0; bit < 8u; ++bit)
            crc = (crc >> 1u) ^
                  (UINT32_C(0xEDB88320) & (uint32_t)-(int32_t)(crc & 1u));
    }
    return ~crc;
}

static void write_u32(uint8_t* output, uint32_t value) {
    for(unsigned shift = 0; shift < 32u; shift += 8u) output[shift / 8u] = value >> shift;
}

static void test_codec_and_validation(void) {
    assert(sizeof(DiagReaderFingerprint) <= 96u);
    assert(DIAG_READER_FINGERPRINT_ENCODED_SIZE <= 192u);
    DiagReaderStats stats = type_a_stats(30000u);
    DiagIsoAIdentity identity = stimulus(0x66);
    DiagReaderFingerprint original;
    assert(diag_reader_fingerprint_from_reader(&stats, &identity, &original));
    uint8_t encoded[DIAG_READER_FINGERPRINT_ENCODED_SIZE];
    assert(diag_reader_fingerprint_encode(&original, encoded, sizeof(encoded)) ==
           sizeof(encoded));
    DiagReaderFingerprint decoded;
    assert(diag_reader_fingerprint_decode(encoded, sizeof(encoded), &decoded));
    uint8_t roundtrip[DIAG_READER_FINGERPRINT_ENCODED_SIZE];
    assert(diag_reader_fingerprint_encode(&decoded, roundtrip, sizeof(roundtrip)) ==
           sizeof(roundtrip));
    assert(!memcmp(encoded, roundtrip, sizeof(encoded)));

    uint8_t damaged[DIAG_READER_FINGERPRINT_ENCODED_SIZE];
    memcpy(damaged, encoded, sizeof(damaged));
    damaged[30] ^= 1u;
    assert(!diag_reader_fingerprint_decode(damaged, sizeof(damaged), &decoded));
    assert(!diag_reader_fingerprint_decode(encoded, sizeof(encoded) - 1u, &decoded));
    memcpy(damaged, encoded, sizeof(damaged));
    damaged[0] = 'X';
    write_u32(damaged + 66u, test_crc32(damaged, 66u));
    assert(!diag_reader_fingerprint_decode(damaged, sizeof(damaged), &decoded));
    memcpy(damaged, encoded, sizeof(damaged));
    damaged[4]++;
    write_u32(damaged + 66u, test_crc32(damaged, 66u));
    assert(!diag_reader_fingerprint_decode(damaged, sizeof(damaged), &decoded));
    memcpy(damaged, encoded, sizeof(damaged));
    damaged[6] = 1u;
    write_u32(damaged + 66u, test_crc32(damaged, 66u));
    assert(!diag_reader_fingerprint_decode(damaged, sizeof(damaged), &decoded));
    memcpy(damaged, encoded, sizeof(damaged));
    damaged[10] |= 0x80u;
    write_u32(damaged + 66u, test_crc32(damaged, 66u));
    assert(!diag_reader_fingerprint_decode(damaged, sizeof(damaged), &decoded));

    original.flags |= 0x80u;
    assert(!diag_reader_fingerprint_encode(&original, encoded, sizeof(encoded)));
}

static void test_recommendations(void) {
    DiagReaderStats classic = {.mode = DiagReaderModeClassic};
    classic.nonce_pairs = 3u;

    DiagInsightRecommendation recommendation;
    assert(diag_insights_recommend(NULL, &classic, NULL, &recommendation));
    assert(strstr(recommendation.cause, "Complete"));
    assert(strstr(recommendation.next_test, "sector"));
    classic.nonce_pairs = 0u;
    assert(diag_insights_recommend(NULL, &classic, NULL, &recommendation));
    assert(strstr(recommendation.next_test, "reader"));

    DiagLfStats lf_fields = {.mode = DiagLfModeReader};
    assert(diag_insights_recommend(NULL, NULL, &lf_fields, &recommendation));
    assert(!strcmp(recommendation.cause, "No reader field sampled."));
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    assert(diag_model_set_error(&model, "app.cancelled", 2));
    assert(diag_insights_recommend(&model, NULL, NULL, &recommendation));
    assert(!strcmp(recommendation.cause, "Test cancelled."));
    assert(!diag_insights_recommend(NULL, NULL, NULL, &recommendation));
    assert(!diag_insights_recommend(&model, NULL, NULL, NULL));
}

int main(void) {
    test_reader_similarity_and_context();
    test_low_evidence_and_zero_denominators();
    test_lf_frequency_heuristic();
    test_codec_and_validation();
    test_recommendations();
    puts("diag_insights tests passed");
    return 0;
}
