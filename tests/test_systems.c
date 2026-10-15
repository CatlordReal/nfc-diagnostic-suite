#include "../diag_systems.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_names(void) {
    assert(diag_system_name_valid(""));
    assert(diag_system_name_valid("Front Door 1"));
    assert(diag_system_name_valid("Lab-A.reader"));
    assert(!diag_system_name_valid(NULL));
    assert(!diag_system_name_valid("."));
    assert(!diag_system_name_valid(".."));
    assert(!diag_system_name_valid(".hidden"));
    assert(!diag_system_name_valid("bad/name"));
    assert(!diag_system_name_valid("bad\\name"));
    assert(!diag_system_name_valid("bad:name"));
    assert(!diag_system_name_valid("bad*name"));
    assert(!diag_system_name_valid("trailing."));
    assert(!diag_system_name_valid("trailing "));
    assert(!diag_system_name_valid("CON"));
    assert(!diag_system_name_valid("com1.txt"));
    assert(!diag_system_name_valid("1234567890123456789012345"));
    assert(!diag_system_name_valid("bad\x1fname"));
    assert(!diag_system_name_valid("caf\xc3\xa9"));
}

static void test_create_limit(void) {
    DiagSystemList list = {0};
    bool exists = false;
    char canonical[DIAG_SYSTEM_NAME_CAPACITY] = {0};
    assert(diag_system_test_create_allowed(&list, "System 1", &exists, canonical));
    assert(!exists && !strcmp(canonical, "System 1"));
    for(size_t index = 0u; index < DIAG_SYSTEM_MAX_GROUPS; ++index) {
        snprintf(list.names[index], sizeof(list.names[index]), "System %u", (unsigned)(index + 1u));
    }
    list.count = DIAG_SYSTEM_MAX_GROUPS;
    assert(!diag_system_test_create_allowed(&list, "System 13", &exists, canonical));
    assert(!exists);
    assert(diag_system_test_create_allowed(&list, "system 12", &exists, canonical));
    assert(exists && !strcmp(canonical, "System 12"));
    list.truncated = true;
    list.count = DIAG_SYSTEM_MAX_GROUPS - 1u;
    assert(!diag_system_test_create_allowed(&list, "Another", &exists, canonical));
}

static void test_paths(void) {
    char path[DIAG_FILES_PATH_CAPACITY];
    assert(diag_system_resolve_directory("", path));
    assert(!strcmp(path, DIAG_SYSTEM_UNGROUPED_DIRECTORY));
    assert(diag_system_resolve_directory("Front Door", path));
    assert(!strcmp(
        path,
        "/ext/apps_data/nfc_diagnostic_suite/systems/Front Door"));
    assert(!diag_system_resolve_directory("../escape", path));

    assert(diag_system_test_profile_path(
        DIAG_SYSTEM_UNGROUPED_DIRECTORY,
        DIAG_SYSTEM_UNGROUPED_DIRECTORY "/20261015-120000.nds",
        path));
    assert(!strcmp(
        path,
        DIAG_SYSTEM_UNGROUPED_DIRECTORY "/20261015-120000.reader"));
    assert(diag_system_test_profile_path(
        DIAG_SYSTEMS_ROOT_DIRECTORY "/Lab",
        DIAG_SYSTEMS_ROOT_DIRECTORY "/Lab/session_1.nds",
        path));
    assert(!strcmp(
        path,
        DIAG_SYSTEMS_ROOT_DIRECTORY "/Lab/session_1.reader"));
    assert(!diag_system_test_profile_path(
        DIAG_SYSTEM_UNGROUPED_DIRECTORY,
        DIAG_SYSTEM_UNGROUPED_DIRECTORY "/nested/card.nds",
        path));
    assert(!diag_system_test_profile_path(
        DIAG_SYSTEM_UNGROUPED_DIRECTORY,
        DIAG_SYSTEMS_ROOT_DIRECTORY "/Lab/card.nds",
        path));
    assert(!diag_system_test_profile_path(
        DIAG_SYSTEM_UNGROUPED_DIRECTORY,
        DIAG_SYSTEM_UNGROUPED_DIRECTORY "/.hidden.nds",
        path));
    assert(!diag_system_test_profile_path(
        DIAG_SYSTEM_UNGROUPED_DIRECTORY,
        DIAG_SYSTEM_UNGROUPED_DIRECTORY "/card.nfc",
        path));
    assert(!diag_system_test_profile_path(
        "/ext/arbitrary",
        "/ext/arbitrary/card.nds",
        path));
}

static void test_current_text(void) {
    char name[DIAG_SYSTEM_NAME_CAPACITY] = "unchanged";
    static const uint8_t valid[] = "Front Door\n";
    assert(diag_system_test_current_decode(valid, sizeof(valid) - 1u, name));
    assert(!strcmp(name, "Front Door"));
    static const uint8_t ungrouped[] = "\n";
    assert(diag_system_test_current_decode(ungrouped, sizeof(ungrouped) - 1u, name));
    assert(!name[0]);

    static const uint8_t no_newline[] = "Lab";
    static const uint8_t two_lines[] = "Lab\nOther\n";
    static const uint8_t carriage[] = "Lab\r\n";
    static const uint8_t invalid_name[] = "../Lab\n";
    assert(!diag_system_test_current_decode(no_newline, sizeof(no_newline) - 1u, name));
    assert(!diag_system_test_current_decode(two_lines, sizeof(two_lines) - 1u, name));
    assert(!diag_system_test_current_decode(carriage, sizeof(carriage) - 1u, name));
    assert(!diag_system_test_current_decode(invalid_name, sizeof(invalid_name) - 1u, name));
    assert(!diag_system_test_current_decode(NULL, 0u, name));
}

static DiagReaderFingerprint make_fingerprint(void) {
    DiagReaderStats stats = {
        .mode = DiagReaderModeField,
        .field_available = true,
        .field_observed = true,
        .elapsed_ms = 30000u,
        .sample_period_ms = 10u,
        .samples = 3000u,
        .field_on_count = 2250u,
        .field_off_count = 750u,
        .field_on_ms = 22500u,
        .field_off_ms = 7500u,
    };
    DiagReaderFingerprint fingerprint;
    assert(diag_reader_fingerprint_from_reader(&stats, NULL, &fingerprint));
    return fingerprint;
}

static void test_profile_codec_trust(void) {
    const DiagReaderFingerprint fingerprint = make_fingerprint();
    uint8_t encoded[DIAG_READER_FINGERPRINT_ENCODED_SIZE + 1u];
    assert(diag_reader_fingerprint_encode(
               &fingerprint, encoded, DIAG_READER_FINGERPRINT_ENCODED_SIZE) ==
           DIAG_READER_FINGERPRINT_ENCODED_SIZE);
    DiagReaderFingerprint decoded;
    assert(diag_system_test_profile_decode(
        encoded, DIAG_READER_FINGERPRINT_ENCODED_SIZE, &decoded));
    assert(!memcmp(&decoded, &fingerprint, sizeof(decoded)));
    assert(!diag_system_test_profile_decode(
        encoded, DIAG_READER_FINGERPRINT_ENCODED_SIZE - 1u, &decoded));
    encoded[DIAG_READER_FINGERPRINT_ENCODED_SIZE] = 0u;
    assert(!diag_system_test_profile_decode(encoded, sizeof(encoded), &decoded));
    encoded[12] ^= 0x80u;
    assert(!diag_system_test_profile_decode(
        encoded, DIAG_READER_FINGERPRINT_ENCODED_SIZE, &decoded));
}

static void test_top_three(void) {
    DiagSystemMatches results = {0};
    const DiagReaderFingerprintMatch insufficient = {
        .result = DiagReaderFingerprintInsufficient,
        .score = 100u,
        .reason = "insufficient",
    };
    diag_system_test_consider_match(&results, "", "ignored", &insufficient);
    assert(results.count == 0u);

    const uint8_t scores[] = {40u, 90u, 60u, 80u, 30u};
    const char* stems[] = {"forty", "ninety", "sixty", "eighty", "thirty"};
    for(size_t index = 0u; index < sizeof(scores); ++index) {
        DiagReaderFingerprintMatch comparison = {
            .result = DiagReaderFingerprintSimilar,
            .score = scores[index],
            .reason = "Similar observed characteristics",
        };
        diag_system_test_consider_match(
            &results, index & 1u ? "Lab" : "", stems[index], &comparison);
    }
    assert(results.count == DIAG_SYSTEM_MAX_MATCHES);
    assert(results.matches[0].score == 90u);
    assert(results.matches[1].score == 80u);
    assert(results.matches[2].score == 60u);
    assert(!strcmp(results.matches[0].session_stem, "ninety"));
    assert(!strcmp(results.matches[0].group, "Lab"));
}

int main(void) {
    test_names();
    test_create_limit();
    test_paths();
    test_current_text();
    test_profile_codec_trust();
    test_top_three();
    puts("diag_systems tests passed");
    return 0;
}
