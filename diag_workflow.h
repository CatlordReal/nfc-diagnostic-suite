#ifndef DIAG_WORKFLOW_H
#define DIAG_WORKFLOW_H

#include "diag_files.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DIAG_WORKFLOW_SOURCE_PATH_CAPACITY 256u
#define DIAG_WORKFLOW_STATE_PATH "/ext/apps_data/nfc_diagnostic_suite/workflow.txt"

typedef enum {
    DiagWorkflowBandUnknown = 0,
    DiagWorkflowBandNfc,
    DiagWorkflowBandLf,
} DiagWorkflowBand;

typedef enum {
    DiagWorkflowActionNone = 0,
    DiagWorkflowActionReadNfc,
    DiagWorkflowActionReadLf,
    DiagWorkflowActionMfkey,
    DiagWorkflowActionWriteNfc,
    DiagWorkflowActionWriteLf,
    DiagWorkflowActionVerify,
    DiagWorkflowActionPicopass,
} DiagWorkflowAction;

typedef enum {
    StepCardReady = 0,
    StepReaderReady,
    StepOutcome,
    StepChooseFile,
    StepSaved,
    StepVerifyCopy,
    StepReread,
} DiagStep;

typedef struct {
    bool started;
    bool have_card;
    DiagWorkflowBand band;
    DiagIsoAIdentity identity;
    char source_path[DIAG_WORKFLOW_SOURCE_PATH_CAPACITY];
    uint32_t pending_action;
} DiagWorkflow;

void diag_workflow_init(DiagWorkflow* workflow, bool have_card);

/* Selects the next local step after a deferred native-tool return. The
   pending action records intent only; this never treats the external action
   as successful. */
DiagStep diag_workflow_resume_step(const DiagWorkflow* workflow, uint32_t returned);

DiagFileStatus diag_workflow_save(
    Storage* storage,
    const DiagWorkflow* workflow,
    FuriString* explanation);

DiagFileStatus diag_workflow_load(
    Storage* storage,
    DiagWorkflow* workflow,
    FuriString* explanation);

#ifdef DIAG_WORKFLOW_TESTING
bool diag_workflow_test_validate(const DiagWorkflow* workflow);
bool diag_workflow_test_parse_bool(const char* text, bool* value);
#endif

#ifdef __cplusplus
}
#endif

#endif
