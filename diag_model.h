#ifndef DIAG_MODEL_H
#define DIAG_MODEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIAG_NFC_PROTOCOL_COUNT 15u
#define DIAG_PROTOCOL_COUNT 16u
#define DIAG_MAX_LOGS 64u
#define DIAG_MAX_ISO_A_UID_BYTES 10u
#define DIAG_MAX_UID_BYTES 32u
#define DIAG_TIMESTAMP_CAPACITY 32u
#define DIAG_ERROR_DOMAIN_CAPACITY 32u
#define DIAG_LOG_MESSAGE_CAPACITY 96u
#define DIAG_PRODUCT_CAPACITY 48u
#define DIAG_VERSION_CAPACITY 48u
#define DIAG_FIRMWARE_BUILD_CAPACITY 48u
#define DIAG_RUNTIME_VERSION_CAPACITY 32u

typedef enum {
    DiagProtocolIso14443_3a = 0,
    DiagProtocolIso14443_3b,
    DiagProtocolIso14443_4a,
    DiagProtocolIso14443_4b,
    DiagProtocolIso15693_3,
    DiagProtocolFelica,
    DiagProtocolMfUltralight,
    DiagProtocolMfClassic,
    DiagProtocolMfPlus,
    DiagProtocolMfDesfire,
    DiagProtocolSlix,
    DiagProtocolSt25tb,
    DiagProtocolNtag4xx,
    DiagProtocolType4Tag,
    DiagProtocolEmv,
    DiagProtocolLfRfid,
} DiagProtocol;

typedef enum {
    DiagProvenanceLive = 0,
    DiagProvenanceSaved,
    DiagProvenanceSimulation,
} DiagProvenance;

typedef enum {
    DiagStageNone = 0,
    DiagStageFieldStarted,
    DiagStageTechnologyDetected,
    DiagStageIdentityRead,
    DiagStageProtocolRead,
    DiagStageMetadataRead,
    DiagStageComplete,
} DiagStage;

typedef enum {
    DiagLogInfo = 0,
    DiagLogSuccess,
    DiagLogWarning,
    DiagLogError,
} DiagLogLevel;

typedef bool (*DiagWriter)(const char* data, size_t size, void* context);

typedef struct {
    DiagLogLevel level;
    DiagStage stage;
    uint32_t elapsed_ms;
    char message[DIAG_LOG_MESSAGE_CAPACITY];
} DiagLogEntry;

typedef struct {
    bool present;
    char domain[DIAG_ERROR_DOMAIN_CAPACITY];
    int32_t code;
} DiagError;

typedef struct {
    bool present;
    uint8_t uid[DIAG_MAX_ISO_A_UID_BYTES];
    size_t uid_size;
    uint8_t atqa[2];
    uint8_t sak;
    uint8_t cascade_count;
} DiagIsoAIdentity;

typedef struct {
    bool present;
    bool may_randomize;
    DiagProtocol protocol;
    uint8_t uid[DIAG_MAX_UID_BYTES];
    size_t uid_size;
} DiagIdentity;

typedef struct {
    char product[DIAG_PRODUCT_CAPACITY];
    char version[DIAG_VERSION_CAPACITY];
} DiagProductMetadata;

typedef struct {
    char firmware_build[DIAG_FIRMWARE_BUILD_CAPACITY];
    char runtime_version[DIAG_RUNTIME_VERSION_CAPACITY];
} DiagRuntimeProvenance;

typedef struct {
    DiagProtocol protocol;
    const char* name;
    const char* family;
    const char* standard;
    const char* diagnostic_note;
} DiagProtocolReference;

typedef struct {
    DiagProvenance provenance;
    DiagProvenance recorded_provenance;
    char timestamp[DIAG_TIMESTAMP_CAPACITY];
    bool run_succeeded;
    DiagStage last_successful_stage;
    DiagError error;
    uint32_t protocol_candidates;
    uint32_t protocols_confirmed;
    DiagIdentity identity;
    DiagIsoAIdentity iso_a;
    DiagProductMetadata metadata;
    DiagRuntimeProvenance runtime;
    DiagLogEntry logs[DIAG_MAX_LOGS];
    size_t log_count;
    size_t logs_dropped;
} DiagModel;

typedef struct {
    bool identity_same;
    bool protocols_same;
    bool metadata_same;
    bool outcome_same;
} DiagComparison;

#define DIAG_REPEATABILITY_RUNS 5u

typedef struct {
    bool run_succeeded;
    DiagStage last_successful_stage;
    DiagError error;
    uint32_t protocol_candidates;
    uint32_t protocols_confirmed;
    DiagIdentity identity;
    DiagIsoAIdentity iso_a;
    DiagProductMetadata metadata;
} DiagObservation;

typedef struct {
    size_t run_count;
    size_t successful_runs;
    size_t failed_runs;
    size_t identity_observed_runs;
    size_t protocol_observed_runs;
    size_t metadata_observed_runs;
    bool identity_repeatable;
    bool protocols_repeatable;
    bool metadata_repeatable;
    bool outcome_repeatable;
} DiagRepeatability;

typedef enum {
    DiagSimulationStableIsoA = 0,
    DiagSimulationFailureIncluded,
    DiagSimulationCandidateOnly,
} DiagSimulationCase;

void diag_model_init(DiagModel* model, DiagProvenance provenance);
bool diag_model_set_timestamp(DiagModel* model, const char* rtc_timestamp);
bool diag_model_add_log(
    DiagModel* model,
    DiagLogLevel level,
    DiagStage stage,
    const char* message);
bool diag_model_add_log_at(
    DiagModel* model,
    DiagLogLevel level,
    DiagStage stage,
    uint32_t elapsed_ms,
    const char* message);
void diag_model_mark_stage_success(DiagModel* model, DiagStage stage);
bool diag_model_set_error(DiagModel* model, const char* domain, int32_t code);
void diag_model_clear_error(DiagModel* model);
bool diag_model_add_protocol_candidate(DiagModel* model, DiagProtocol protocol);

/* Confirmed protocols require live provenance and direct parent-supplied API evidence. */
bool diag_model_confirm_protocol(
    DiagModel* model,
    DiagProtocol protocol,
    bool has_direct_api_evidence);

bool diag_model_set_iso_a_identity(
    DiagModel* model,
    const uint8_t* uid,
    size_t uid_size,
    const uint8_t atqa[2],
    uint8_t sak);
bool diag_model_set_identity(
    DiagModel* model,
    DiagProtocol protocol,
    const uint8_t* uid,
    size_t uid_size);
bool diag_model_set_product_metadata(
    DiagModel* model,
    const char* product,
    const char* version);
bool diag_model_set_runtime_provenance(
    DiagModel* model,
    const char* firmware_build,
    const char* runtime_version);

const char* diag_protocol_name(DiagProtocol protocol);
const char* diag_provenance_name(DiagProvenance provenance);
const char* diag_stage_name(DiagStage stage);
const char* diag_log_level_name(DiagLogLevel level);
const DiagProtocolReference* diag_protocol_reference(DiagProtocol protocol);
const char* diag_stage_advice(DiagStage stage);

DiagComparison diag_model_compare(const DiagModel* left, const DiagModel* right);
bool diag_model_observe(const DiagModel* model, DiagObservation* observation);
bool diag_observations_analyze(
    const DiagObservation observations[DIAG_REPEATABILITY_RUNS],
    DiagRepeatability* result);
bool diag_repeatability_analyze(
    const DiagModel* const runs[DIAG_REPEATABILITY_RUNS],
    DiagRepeatability* result);

bool diag_model_export_json(const DiagModel* model, DiagWriter writer, void* context);
bool diag_model_export_csv(const DiagModel* model, DiagWriter writer, void* context);

bool diag_model_load_simulation(
    DiagModel* model,
    DiagSimulationCase simulation,
    size_t run_index);

/* Small on-device check using the same comparison and repeatability paths as host tests. */
bool diag_model_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
