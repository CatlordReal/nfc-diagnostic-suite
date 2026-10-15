#ifndef DIAG_INSIGHTS_H
#define DIAG_INSIGHTS_H

#include "diag_lf.h"
#include "diag_reader.h"

#define DIAG_READER_FINGERPRINT_VERSION 1u
#define DIAG_READER_FINGERPRINT_ENCODED_SIZE 70u

typedef enum {
    DiagReaderFingerprintKindNfc = 1,
    DiagReaderFingerprintKindLfFields = 2,
} DiagReaderFingerprintKind;

enum {
    DiagReaderFingerprintHasField = 1u << 0,
    DiagReaderFingerprintHasNfcField = 1u << 1,
    DiagReaderFingerprintHasSelection = 1u << 2,
    DiagReaderFingerprintHasTraffic = 1u << 3,
    DiagReaderFingerprintHasStimulus = 1u << 4,
    DiagReaderFingerprintSyntheticStimulus = 1u << 5,
    DiagReaderFingerprintHasFrequency = 1u << 6,
};

/* Compact observed-characteristics profile. Values describe one bounded probe;
   they are heuristics, not a reader identity, RF strength, or calibrated metrology. */
typedef struct {
    uint32_t elapsed_ms;
    uint32_t frequency_hz_min;
    uint32_t frequency_hz_max;
    uint32_t frequency_hz_last;
    uint16_t sample_period_ms;
    uint16_t field_duty_permille;
    uint16_t nfc_field_duty_permille;
    uint16_t field_edge_rate_per_min;
    uint16_t selection_rate_per_min;
    uint16_t request_rate_per_min;
    uint16_t auth_rate_per_min;
    uint16_t error_rate_per_min;
    uint16_t min_request_gap_ms;
    uint16_t max_request_gap_ms;
    uint16_t sample_count;
    uint16_t evidence_count;
    uint8_t stimulus_uid[DIAG_MAX_ISO_A_UID_BYTES];
    uint8_t stimulus_atqa[2];
    uint8_t version;
    uint8_t kind;
    uint8_t mode;
    uint8_t flags;
    uint8_t stimulus_uid_size;
    uint8_t stimulus_sak;
} DiagReaderFingerprint;

typedef enum {
    DiagReaderFingerprintInvalid = 0,
    DiagReaderFingerprintInsufficient,
    DiagReaderFingerprintNotComparable,
    DiagReaderFingerprintSimilar,
    DiagReaderFingerprintDifferent,
} DiagReaderFingerprintResult;

typedef struct {
    DiagReaderFingerprintResult result;
    uint8_t score;
    const char* reason;
} DiagReaderFingerprintMatch;

bool diag_reader_fingerprint_from_reader(
    const DiagReaderStats* stats,
    const DiagIsoAIdentity* optional_stimulus,
    DiagReaderFingerprint* fingerprint);
bool diag_reader_fingerprint_from_fields(
    const DiagLfStats* stats,
    DiagReaderFingerprint* fingerprint);

/* Fixed 70-byte, little-endian, versioned encoding with CRC32. */
size_t diag_reader_fingerprint_encode(
    const DiagReaderFingerprint* fingerprint,
    uint8_t* output,
    size_t capacity);
bool diag_reader_fingerprint_decode(
    const uint8_t* data,
    size_t size,
    DiagReaderFingerprint* fingerprint);

/* Returns Similar only for comparable, sufficiently rich observations. */
DiagReaderFingerprintMatch diag_reader_fingerprint_compare(
    const DiagReaderFingerprint* left,
    const DiagReaderFingerprint* right);

typedef struct {
    const char* cause;
    const char* next_test;
} DiagInsightRecommendation;

/* All inputs are optional. Returned strings are static and contain no inferred
   reader brand, credential, RF strength, or unobserved protocol claim. */
bool diag_insights_recommend(
    const DiagModel* model,
    const DiagReaderStats* reader,
    const DiagLfStats* fields,
    DiagInsightRecommendation* recommendation);

#endif
