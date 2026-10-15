#ifndef DIAG_CAPABILITIES_H
#define DIAG_CAPABILITIES_H

#include "diag_model.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool has_identity;
    bool is_nfc;
    bool is_lf;
    bool classic;
    bool can_native_write;
    bool can_magic_write;
    bool can_emulate;
    bool complete_dump_required;
    const char* limitation;
    const char* native_tool;
} DiagCapabilities;

typedef enum {
    DiagCapabilityActionGuide = 0,
    DiagCapabilityActionFindCard = 1,
    DiagCapabilityActionReaderTests = 2,
    DiagCapabilityActionReadNfc = 3,
    DiagCapabilityActionReadLf = 4,
    DiagCapabilityActionSourceNfc = 5,
    DiagCapabilityActionSourceLf = 6,
    DiagCapabilityActionCaptureClassic = 7,
    DiagCapabilityActionMfkey = 8,
    DiagCapabilityActionWriteNfc = 9,
    DiagCapabilityActionWriteLf = 10,
    DiagCapabilityActionVerify = 11,
    DiagCapabilityActionSave = 12,
    DiagCapabilityActionNew = 13,
    DiagCapabilityActionPicopass = 14,
    DiagCapabilityActionNonceLibrary = 15,
} DiagCapabilityActionId;

DiagCapabilities diag_capabilities_for(const DiagModel* model);

/* Returns actions written; never exceeds capacity. NULL output writes none. */
size_t diag_capabilities_workflow_actions(
    DiagCapabilities capabilities,
    unsigned band,
    bool have_card,
    bool has_source,
    bool has_nonce_pairs,
    unsigned* actions,
    size_t capacity);

#ifdef __cplusplus
}
#endif

#endif
