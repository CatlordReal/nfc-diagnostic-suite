#ifndef DIAG_READER_H
#define DIAG_READER_H

#include "diag_model.h"

#define DIAG_READER_DURATION_MS 30000u
#define DIAG_READER_FIELD_SAMPLE_MS 10u
#define DIAG_READER_MAX_PAIRS 8u
#define DIAG_READER_NONCE_LOG_PATH "/ext/nfc/.mfkey32.log"

typedef enum {
    DiagReaderModeField = 0,
    DiagReaderModeTypeA,
    DiagReaderModeClassic,
} DiagReaderMode;

typedef struct {
    DiagReaderMode mode;
    bool field_available;
    bool field_present;
    bool field_observed;
    bool selection_available;
    bool rx_total_available;
    bool synthetic_identity;
    bool inconclusive;
    uint32_t elapsed_ms;
    uint32_t sample_period_ms;
    uint32_t samples;
    uint32_t field_on_count;
    uint32_t field_off_count;
    uint32_t field_on_ms;
    uint32_t field_off_ms;
    uint32_t last_field_change_ms;
    uint32_t selection_count;
    uint32_t rx_count;
    uint32_t request_count;
    uint32_t auth_request_count;
    uint32_t error_count;
    uint32_t events_dropped;
    uint32_t first_request_ms;
    uint32_t last_request_ms;
    uint32_t min_request_gap_ms;
    uint32_t max_request_gap_ms;
    uint32_t transcripts_collected;
    uint32_t transcript_duplicates;
    uint32_t transcript_rejected;
    uint32_t nonce_pairs;
    uint32_t pairs_saved;
    uint32_t pairs_already_saved;
    uint32_t auth_full_count;
    int32_t storage_error;
} DiagReaderStats;

typedef struct DiagReader DiagReader;

/* The caller serializes start/free. Cancel and snapshot are thread-safe. */
DiagReader* diag_reader_alloc(void);
void diag_reader_free(DiagReader* instance);
bool diag_reader_start(
    DiagReader* instance, DiagReaderMode mode, const DiagIsoAIdentity* optional_identity);
void diag_reader_cancel(DiagReader* instance);
bool diag_reader_is_running(DiagReader* instance);
void diag_reader_snapshot(
    DiagReader* instance, DiagModel* model, DiagReaderStats* stats);
/* Configured probe stimulus, never observed card/reader evidence. */
void diag_reader_stimulus(DiagReader* instance, DiagIsoAIdentity* identity);
bool diag_reader_read_model(
    DiagReader* instance, DiagModelReadCallback callback, void* context);

const char* diag_reader_mode_name(DiagReaderMode mode);

typedef struct Storage Storage;
typedef struct FuriString FuriString;
typedef struct {
    bool exists;
    bool truncated;
    uint64_t size_bytes;
    uint32_t valid_pair_lines;
    uint32_t malformed_lines;
    uint32_t oversized_lines;
    bool system_dictionary_exists;
    bool user_dictionary_exists;
    bool system_dictionary_complete;
    bool user_dictionary_complete;
    uint32_t system_dictionary_entries;
    uint32_t user_dictionary_entries;
    int32_t error;
} DiagNonceLibraryInfo;

/* Read-only, at most 1 MiB per log/dictionary; never returns key or transcript contents. */
bool diag_reader_library_info(Storage* storage, DiagNonceLibraryInfo* info, FuriString* explanation);

#ifdef DIAG_READER_TESTING
bool diag_reader_test_stimulus(
    DiagReaderMode mode, const DiagIsoAIdentity* source, const uint8_t random_uid[4],
    DiagIsoAIdentity* result, bool* synthetic);
typedef struct DiagReaderTest DiagReaderTest;
typedef enum {
    DiagReaderTestFieldOn,
    DiagReaderTestFieldOff,
    DiagReaderTestSelected,
    DiagReaderTestRx,
    DiagReaderTestError,
    DiagReaderTestSampleOff,
    DiagReaderTestSampleOn,
} DiagReaderTestEvent;
DiagReaderTest* diag_reader_test_alloc(DiagReaderMode mode);
void diag_reader_test_free(DiagReaderTest* instance);
void diag_reader_test_event(
    DiagReaderTest* instance, DiagReaderTestEvent event, uint32_t elapsed_ms,
    uint8_t opcode, uint16_t frame_bits);
bool diag_reader_test_auth_frame(
    DiagReaderTest* instance, uint32_t elapsed_ms, uint32_t cuid,
    uint8_t block, bool key_b, const uint8_t nt[4], const uint8_t* reader_frame,
    size_t reader_frame_size);
void diag_reader_test_snapshot(
    const DiagReaderTest* instance, DiagModel* model, DiagReaderStats* stats);
size_t diag_reader_test_pair_line(
    const DiagReaderTest* instance, size_t index, char* output, size_t capacity);
bool diag_reader_test_pair_lines_equal(const char* left, const char* right);
void diag_reader_test_library(const uint8_t* data, size_t size, DiagNonceLibraryInfo* info);
#endif

#endif
