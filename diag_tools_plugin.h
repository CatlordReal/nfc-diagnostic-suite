#ifndef DIAG_TOOLS_PLUGIN_H
#define DIAG_TOOLS_PLUGIN_H

#include "diag_insights.h"
#include "diag_systems_ui.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIAG_TOOLS_PLUGIN_APP_ID "nfc_diagnostic_suite"
#define DIAG_TOOLS_PLUGIN_API_VERSION 1u

typedef struct {
    bool (*recommend)(
        const DiagModel* model,
        const DiagReaderStats* reader,
        const DiagLfStats* fields,
        DiagInsightRecommendation* recommendation);
    bool (*from_reader)(
        const DiagReaderStats* stats,
        const DiagIsoAIdentity* optional_stimulus,
        DiagReaderFingerprint* fingerprint);
    bool (*from_fields)(const DiagLfStats* stats, DiagReaderFingerprint* fingerprint);
    bool (*resolve_directory)(
        const char* name,
        char output[DIAG_FILES_PATH_CAPACITY]);
    DiagFileStatus (*current_load)(
        Storage* storage,
        char name[DIAG_SYSTEM_NAME_CAPACITY],
        FuriString* explanation);
    DiagFileStatus (*save_reader_profile)(
        Storage* storage,
        const char* directory,
        const char* session_path,
        const DiagReaderFingerprint* fingerprint,
        char output_path[DIAG_FILES_PATH_CAPACITY],
        FuriString* explanation);
    DiagFileStatus (*find_similar)(
        Storage* storage,
        const DiagReaderFingerprint* current,
        DiagSystemMatches* results,
        FuriString* explanation);
    bool (*choose)(
        Storage* storage,
        Gui* gui,
        char name[DIAG_SYSTEM_NAME_CAPACITY],
        FuriString* explanation);
} DiagToolsApi;

#ifdef __cplusplus
}
#endif

#endif
