#ifndef DIAG_FILES_H
#define DIAG_FILES_H

#include "diag_model.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DIAG_FILES_MAX_INPUT_SIZE (256u * 1024u)
#define DIAG_FILES_MAX_SESSION_PAYLOAD (32u * 1024u)
#define DIAG_FILES_PATH_CAPACITY 256u
#define DIAG_FILES_COMPARISON_DETAIL_CAPACITY 192u

typedef struct Storage Storage;
typedef struct FuriString FuriString;

typedef enum {
    DiagFileStatusOk = 0,
    DiagFileStatusInvalidArgument,
    DiagFileStatusNotFound,
    DiagFileStatusTooLarge,
    DiagFileStatusInvalidFormat,
    DiagFileStatusUnsupported,
    DiagFileStatusIntegrity,
    DiagFileStatusExists,
    DiagFileStatusIo,
    DiagFileStatusPartial,
} DiagFileStatus;

typedef struct {
    char json_path[DIAG_FILES_PATH_CAPACITY];
    char csv_path[DIAG_FILES_PATH_CAPACITY];
    char session_path[DIAG_FILES_PATH_CAPACITY];
    DiagFileStatus json_status;
    DiagFileStatus csv_status;
} DiagFilesExportResult;

typedef enum {
    DiagSavedReadCompletenessUnknown = 0,
    DiagSavedReadCompletenessComplete,
    DiagSavedReadCompletenessIncomplete,
} DiagSavedReadCompleteness;

typedef struct {
    bool equal;
    DiagSavedReadCompleteness left_completeness;
    DiagSavedReadCompleteness right_completeness;
    char detail[DIAG_FILES_COMPARISON_DETAIL_CAPACITY];
} DiagSavedComparison;

const char* diag_file_status_string(DiagFileStatus status);

/* Creates each child below the VFS mount and verifies existing entries are directories. */
DiagFileStatus diag_files_ensure_directory(
    Storage* storage,
    const char* directory,
    FuriString* explanation);

/* Preflight runs before Momentum's semantic loader. Loaded files are saved evidence only. */
DiagFileStatus diag_files_validate_nfc(
    Storage* storage,
    const char* path,
    DiagModel* out,
    FuriString* explanation);

DiagFileStatus diag_files_validate_rfid(
    Storage* storage,
    const char* path,
    DiagModel* out,
    FuriString* explanation);

/* Equality covers decoded saved-file data only; detail reports source read completeness. */
DiagFileStatus diag_files_compare_saved_nfc(
    Storage* storage,
    const char* left_path,
    const char* right_path,
    DiagSavedComparison* result,
    FuriString* explanation);

DiagFileStatus diag_files_compare_saved_rfid(
    Storage* storage,
    const char* left_path,
    const char* right_path,
    DiagSavedComparison* result,
    FuriString* explanation);

DiagFileStatus diag_files_save_session(
    Storage* storage,
    const char* path,
    const DiagModel* model,
    FuriString* explanation);

DiagFileStatus diag_files_load_session(
    Storage* storage,
    const char* path,
    DiagModel* out,
    FuriString* explanation);

/* Chooses one unused basename for .json, .csv, and .nds; publishes each report atomically. */
DiagFileStatus diag_files_export_reports(
    Storage* storage,
    const char* directory,
    const char* basename,
    const DiagModel* model,
    DiagFilesExportResult* result,
    FuriString* explanation);

#ifdef DIAG_FILES_TESTING
typedef int32_t (*DiagFilesTestMkdir)(void* context, const char* path);
typedef int32_t (*DiagFilesTestStatDir)(void* context, const char* path, bool* is_directory);

DiagFileStatus diag_files_test_preflight_nfc(
    const uint8_t* data,
    size_t size,
    DiagProtocol* protocol);
DiagFileStatus diag_files_test_preflight_rfid(
    const uint8_t* data,
    size_t size,
    const char* expected_protocol,
    size_t expected_data_size);
DiagFileStatus diag_files_test_session_roundtrip(
    const DiagModel* model,
    DiagModel* out,
    uint8_t* encoded,
    size_t encoded_capacity,
    size_t* encoded_size);
DiagFileStatus diag_files_test_session_decode(
    const uint8_t* encoded,
    size_t encoded_size,
    DiagModel* out);
bool diag_files_test_heap_sufficient(
    size_t free_heap,
    size_t max_free_block,
    size_t requested_total,
    size_t largest_allocation);
int32_t diag_files_test_ensure_directory(
    const char* directory,
    DiagFilesTestMkdir mkdir_operation,
    DiagFilesTestStatDir stat_operation,
    void* context,
    int32_t ok_code,
    int32_t exists_code,
    int32_t invalid_code,
    char* failed_path,
    size_t failed_path_capacity);
#endif

#ifdef __cplusplus
}
#endif

#endif
