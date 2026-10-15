#ifndef DIAG_SYSTEMS_H
#define DIAG_SYSTEMS_H

#include "diag_files.h"
#include "diag_insights.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIAG_SYSTEM_NAME_CAPACITY 25u
#define DIAG_SYSTEM_MAX_GROUPS 12u
#define DIAG_SYSTEM_MAX_PROFILES 64u
#define DIAG_SYSTEM_MAX_MATCHES 3u
#define DIAG_SYSTEM_SESSION_STEM_CAPACITY 65u
#define DIAG_SYSTEM_MATCH_REASON_CAPACITY 96u
#define DIAG_SYSTEM_UNGROUPED_DIRECTORY "/ext/apps_data/nfc_diagnostic_suite"
#define DIAG_SYSTEMS_ROOT_DIRECTORY DIAG_SYSTEM_UNGROUPED_DIRECTORY "/systems"

typedef struct {
    char names[DIAG_SYSTEM_MAX_GROUPS][DIAG_SYSTEM_NAME_CAPACITY];
    size_t count;
    bool truncated;
} DiagSystemList;

typedef struct {
    char group[DIAG_SYSTEM_NAME_CAPACITY]; /* Empty means ungrouped. */
    char session_stem[DIAG_SYSTEM_SESSION_STEM_CAPACITY];
    uint8_t score;
    char reason[DIAG_SYSTEM_MATCH_REASON_CAPACITY];
} DiagSystemMatch;

typedef struct {
    DiagSystemMatch matches[DIAG_SYSTEM_MAX_MATCHES];
    size_t count;
    uint16_t files_seen;
    uint16_t files_decoded;
    uint16_t invalid_files;
    uint16_t insufficient_files;
    uint16_t not_comparable_files;
    bool truncated;
} DiagSystemMatches;

bool diag_system_name_valid(const char* name);
bool diag_system_resolve_directory(
    const char* name,
    char output[DIAG_FILES_PATH_CAPACITY]);

DiagFileStatus diag_system_list(
    Storage* storage,
    DiagSystemList* list,
    FuriString* explanation);
DiagFileStatus diag_system_create(
    Storage* storage,
    const char* name,
    FuriString* explanation);
DiagFileStatus diag_system_current_load(
    Storage* storage,
    char name[DIAG_SYSTEM_NAME_CAPACITY],
    FuriString* explanation);
DiagFileStatus diag_system_current_save(
    Storage* storage,
    const char* name,
    FuriString* explanation);

/* Saves one fixed-size reader observation beside an already-saved .nds session. */
DiagFileStatus diag_system_save_reader_profile(
    Storage* storage,
    const char* directory,
    const char* session_path,
    const DiagReaderFingerprint* fingerprint,
    char output_path[DIAG_FILES_PATH_CAPACITY],
    FuriString* explanation);

/* Returns only Similar results. Empty group means ungrouped. Never identifies a reader. */
DiagFileStatus diag_system_find_similar(
    Storage* storage,
    const DiagReaderFingerprint* current,
    DiagSystemMatches* results,
    FuriString* explanation);

#ifdef DIAG_SYSTEMS_TESTING
bool diag_system_test_profile_path(
    const char* directory,
    const char* session_path,
    char output[DIAG_FILES_PATH_CAPACITY]);
bool diag_system_test_current_decode(
    const uint8_t* data,
    size_t size,
    char name[DIAG_SYSTEM_NAME_CAPACITY]);
bool diag_system_test_profile_decode(
    const uint8_t* data,
    size_t size,
    DiagReaderFingerprint* fingerprint);
void diag_system_test_consider_match(
    DiagSystemMatches* results,
    const char* group,
    const char* session_stem,
    const DiagReaderFingerprintMatch* comparison);
bool diag_system_test_create_allowed(
    const DiagSystemList* list,
    const char* name,
    bool* exists,
    char canonical[DIAG_SYSTEM_NAME_CAPACITY]);
#endif

#ifdef __cplusplus
}
#endif

#endif
