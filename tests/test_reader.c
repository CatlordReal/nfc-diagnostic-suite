#include "../diag_reader.h"
#include "../diag_insights.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void number_bytes(uint32_t value, uint8_t bytes[4]) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void auth(
    DiagReaderTest* reader, uint32_t time, uint32_t cuid, uint8_t block,
    bool key_b, uint32_t nt, uint32_t nr, uint32_t ar) {
    uint8_t nonce[4], frame[8];
    number_bytes(nt, nonce);
    number_bytes(nr, frame);
    number_bytes(ar, frame + 4);
    assert(diag_reader_test_auth_frame(reader, time, cuid, block, key_b, nonce, frame, sizeof(frame)));
}

static void test_passive_field(void) {
    DiagReaderTest* reader = diag_reader_test_alloc(DiagReaderModeField);
    assert(reader);
    diag_reader_test_event(reader, DiagReaderTestSampleOff, 0, 0, 0);
    diag_reader_test_event(reader, DiagReaderTestSampleOn, 10, 0, 0);
    diag_reader_test_event(reader, DiagReaderTestSampleOn, 20, 0, 0);
    diag_reader_test_event(reader, DiagReaderTestSampleOff, 35, 0, 0);
    DiagReaderStats stats;
    DiagModel model;
    diag_reader_test_snapshot(reader, &model, &stats);
    assert(stats.samples == 4 && stats.field_on_count == 1 && stats.field_off_count == 1);
    assert(stats.field_on_ms == 25 && stats.field_off_ms == 10);
    assert(stats.field_observed && !stats.field_present);
    assert(stats.sample_period_ms == DIAG_READER_FIELD_SAMPLE_MS);
    assert(stats.inconclusive && !stats.selection_available && !stats.rx_total_available);
    assert(model.protocols_confirmed == 0);
    diag_reader_test_free(reader);
}

static void test_type_a_metadata(void) {
    DiagReaderTest* reader = diag_reader_test_alloc(DiagReaderModeTypeA);
    assert(reader);
    diag_reader_test_event(reader, DiagReaderTestFieldOn, 5, 0, 0);
    diag_reader_test_event(reader, DiagReaderTestSelected, 7, 0, 0);
    diag_reader_test_event(reader, DiagReaderTestRx, 10, 0x60, 32);
    diag_reader_test_event(reader, DiagReaderTestRx, 22, 0x61, 32);
    diag_reader_test_event(reader, DiagReaderTestRx, 50, 0x30, 32);
    diag_reader_test_event(reader, DiagReaderTestFieldOff, 70, 0, 0);
    DiagReaderStats stats;
    DiagModel model;
    diag_reader_test_snapshot(reader, &model, &stats);
    assert(stats.selection_count == 1 && stats.rx_count == 3 && stats.request_count == 3);
    assert(stats.auth_request_count == 2 && stats.transcripts_collected == 0 && stats.nonce_pairs == 0);
    assert(stats.first_request_ms == 10 && stats.last_request_ms == 50);
    assert(stats.min_request_gap_ms == 12 && stats.max_request_gap_ms == 28);
    assert(stats.field_on_ms == 65 && !stats.inconclusive);
    assert(model.protocols_confirmed == (1u << DiagProtocolIso14443_3a));
    assert(model.protocol_candidates & (1u << DiagProtocolMfClassic));
    assert(!(model.protocols_confirmed & (1u << DiagProtocolMfClassic)));
    diag_reader_test_free(reader);
}

static void test_complete_matching_pairs(void) {
    DiagReaderTest* reader = diag_reader_test_alloc(DiagReaderModeClassic);
    assert(reader);
    uint8_t nonce[4] = {1, 2, 3, 4}, short_frame[4] = {5, 6, 7, 8};
    assert(!diag_reader_test_auth_frame(reader, 1, 0x12345678, 4, false,
                                       nonce, short_frame, sizeof(short_frame)));
    DiagReaderStats stats;
    DiagModel model;
    diag_reader_test_snapshot(reader, &model, &stats);
    assert(stats.error_count == 1 && stats.nonce_pairs == 0 && model.protocols_confirmed == 0);
    auth(reader, 2, 0x12345678, 4, false, 0x01020304, 0x11121314, 0x21222324);
    diag_reader_test_snapshot(reader, NULL, &stats);
    assert(stats.transcripts_collected == 1 && stats.nonce_pairs == 0 && stats.inconclusive);
    auth(reader, 3, 0x12345678, 4, false, 0x01020304, 0x11121314, 0x21222324);
    auth(reader, 4, 0x12345678, 4, true, 0x02030405, 0x12131415, 0x22232425);
    auth(reader, 5, 0x12345679, 4, false, 0x02030405, 0x12131415, 0x22232425);
    auth(reader, 6, 0x12345678, 8, false, 0x02030405, 0x12131415, 0x22232425);
    diag_reader_test_snapshot(reader, NULL, &stats);
    assert(stats.transcript_duplicates == 1 && stats.nonce_pairs == 0);
    /* Block 7 shares sector 1 with block 4; CUID and key type still match. */
    auth(reader, 7, 0x12345678, 7, false, 0x02030405, 0x12131415, 0x22232425);
    diag_reader_test_snapshot(reader, &model, &stats);
    assert(stats.nonce_pairs == 1 && !stats.inconclusive);
    assert(!stats.field_available && !stats.selection_available && !stats.rx_total_available);
    assert(model.protocols_confirmed & (1u << DiagProtocolMfClassic));
    char line[192];
    assert(diag_reader_test_pair_line(reader, 0, line, sizeof(line)) > 0);
    assert(strcmp(line, "Sec 1 key A cuid 12345678 nt0 01020304 nr0 11121314 ar0 21222324 nt1 02030405 nr1 12131415 ar1 22232425\n") == 0);
    char small[8] = {0};
    assert(diag_reader_test_pair_line(reader, 0, small, sizeof(small)) == 0);
    assert(diag_reader_test_pair_line(reader, 1, line, sizeof(line)) == 0);
    diag_reader_test_free(reader);
}

static void test_shared_components_and_full_replay(void) {
    DiagReaderTest* reader = diag_reader_test_alloc(DiagReaderModeClassic);
    auth(reader, 1, 1, 255, true, 1, 2, 3);
    auth(reader, 2, 1, 255, true, 1, 12, 13);
    auth(reader, 3, 1, 255, true, 11, 2, 13);
    auth(reader, 4, 1, 255, true, 11, 12, 3);
    DiagReaderStats stats;
    diag_reader_test_snapshot(reader, NULL, &stats);
    assert(stats.nonce_pairs == 3 && stats.transcript_rejected == 0);
    auth(reader, 5, 1, 255, true, 1, 2, 3);
    diag_reader_test_snapshot(reader, NULL, &stats);
    assert(stats.nonce_pairs == 3 && stats.transcript_duplicates == 1);
    auth(reader, 5, 1, 255, true, 11, 12, 13);
    diag_reader_test_snapshot(reader, NULL, &stats);
    assert(stats.nonce_pairs == 4);
    char line[192];
    assert(diag_reader_test_pair_line(reader, 0, line, sizeof(line)));
    assert(strncmp(line, "Sec 39 key B", 12) == 0);
    assert(diag_reader_test_pair_lines_equal(line, line));
    DiagNonceLibraryInfo info;
    diag_reader_test_library((const uint8_t*)line, strlen(line), &info);
    assert(info.valid_pair_lines == 1 && info.malformed_lines == 0);
    const char* replay = "Sec 39 key B cuid 00000001 nt0 00000001 nr0 00000002 ar0 00000003 nt1 00000001 nr1 00000002 ar1 00000003\n";
    assert(!diag_reader_test_pair_lines_equal(replay, replay));
    diag_reader_test_free(reader);
}

static void test_pair_bound(void) {
    DiagReaderTest* reader = diag_reader_test_alloc(DiagReaderModeClassic);
    auth(reader, 0, 1, 0, false, 1, 2, 3);
    for(uint32_t index = 0; index < 64; ++index) {
        auth(reader, index + 1, 1, 0, false, 10 + index, 100 + index, 1000 + index);
    }
    DiagReaderStats stats;
    diag_reader_test_snapshot(reader, NULL, &stats);
    assert(stats.nonce_pairs == DIAG_READER_MAX_PAIRS && stats.transcript_rejected > 0);
    diag_reader_test_free(reader);
}

static void test_native_log_dedup_and_scan(void) {
    const char* line = "Sec 1 key A cuid aabbccdd nt0 01020304 nr0 11121314 ar0 21222324 nt1 02030405 nr1 12131415 ar1 22232425\n";
    const char* reversed = "Sec 1 key A cuid AABBCCDD nt0 02030405 nr0 12131415 ar0 22232425 nt1 01020304 nr1 11121314 ar1 21222324\r\n";
    const char* other_key = "Sec 1 key B cuid aabbccdd nt0 01020304 nr0 11121314 ar0 21222324 nt1 02030405 nr1 12131415 ar1 22232425\n";
    assert(diag_reader_test_pair_lines_equal(line, reversed));
    assert(!diag_reader_test_pair_lines_equal(line, other_key));
    assert(!diag_reader_test_pair_lines_equal(line, "Sec 1 key A cuid 1"));
    assert(!diag_reader_test_pair_lines_equal(line, ""));
    for(size_t digits = 0; digits < 8; ++digits) {
        const char* prefix = "Sec 1 key A cuid ";
        size_t size = strlen(prefix) + digits + 1;
        char* partial = malloc(size);
        assert(partial);
        memcpy(partial, prefix, strlen(prefix));
        memset(partial + strlen(prefix), 'a', digits);
        partial[size - 1] = '\0';
        assert(!diag_reader_test_pair_lines_equal(line, partial));
        free(partial);
        char poisoned[64];
        memset(poisoned, 'a', sizeof(poisoned));
        memcpy(poisoned, prefix, strlen(prefix));
        poisoned[strlen(prefix) + digits] = '\0';
        assert(!diag_reader_test_pair_lines_equal(line, poisoned));
    }
    char data[1024];
    int size = snprintf(data, sizeof(data), "%sbad line\n%s", line, reversed);
    assert(size > 0);
    memset(data + size, 'X', 300);
    size += 300;
    data[size++] = '\n';
    char backup[1024];
    memcpy(backup, data, sizeof(data));
    DiagNonceLibraryInfo info;
    diag_reader_test_library((const uint8_t*)data, (size_t)size, &info);
    assert(info.valid_pair_lines == 2 && info.malformed_lines == 1 && info.oversized_lines == 1);
    assert(memcmp(data, backup, sizeof(data)) == 0);
    /* Every short prefix, including mid-hex tokens, must remain bounded. */
    for(size_t prefix = 0; prefix < strlen(line); ++prefix) {
        char partial[192];
        memcpy(partial, line, prefix);
        partial[prefix] = '\0';
        (void)diag_reader_test_pair_lines_equal(line, partial);
    }
}

static void test_native_stimulus_profiles(void) {
    const uint8_t random_uid[4] = {1, 2, 3, 4};
    DiagIsoAIdentity identity;
    bool synthetic;
    DiagReaderFingerprint profile;
    uint8_t encoded[DIAG_READER_FINGERPRINT_ENCODED_SIZE];
    for(unsigned mode = DiagReaderModeField; mode <= DiagReaderModeClassic; ++mode) {
        assert(diag_reader_test_stimulus((DiagReaderMode)mode, NULL, random_uid, &identity, &synthetic));
        assert(identity.present == (mode != DiagReaderModeField));
        assert(synthetic == (mode != DiagReaderModeField));
        if(identity.present) { assert(identity.uid[0] == 0x08); assert(identity.cascade_count == 1); }
        DiagReaderStats stats = {.mode = (DiagReaderMode)mode, .synthetic_identity = synthetic, .elapsed_ms = 30000};
        assert(diag_reader_fingerprint_from_reader(&stats, identity.present ? &identity : NULL, &profile));
        assert(diag_reader_fingerprint_encode(&profile, encoded, sizeof(encoded)) == sizeof(encoded));
        assert(diag_reader_fingerprint_decode(encoded, sizeof(encoded), &profile));
    }
    DiagIsoAIdentity supplied = {.present = true, .uid_size = 7, .uid = {4, 1, 2, 3, 4, 5, 6}, .cascade_count = 2};
    assert(diag_reader_test_stimulus(DiagReaderModeClassic, &supplied, NULL, &identity, &synthetic));
    assert(!synthetic && identity.sak == 0x18 && identity.atqa[0] == 0x42 && identity.cascade_count == 2);
    assert(!memcmp(identity.uid, supplied.uid, 7));
    supplied.uid_size = 10;
    assert(!diag_reader_test_stimulus(DiagReaderModeClassic, &supplied, NULL, &identity, &synthetic));
}

int main(void) {
    test_native_stimulus_profiles();
    test_passive_field();
    test_type_a_metadata();
    test_complete_matching_pairs();
    test_shared_components_and_full_replay();
    test_pair_bound();
    test_native_log_dedup_and_scan();
    puts("diag_reader callback/evidence tests passed");
    return EXIT_SUCCESS;
}
