#include "../diag_workflow.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_init(void) {
    DiagWorkflow workflow;
    memset(&workflow, 0xA5, sizeof(workflow));
    diag_workflow_init(&workflow, true);
    assert(workflow.started);
    assert(workflow.have_card);
    assert(workflow.band == DiagWorkflowBandUnknown);
    assert(!workflow.identity.present);
    assert(workflow.identity.uid_size == 0u);
    assert(workflow.source_path[0] == '\0');
    assert(workflow.pending_action == DiagWorkflowActionNone);
    assert(diag_workflow_test_validate(&workflow));
}

static void test_valid_nfc(void) {
    DiagWorkflow workflow;
    diag_workflow_init(&workflow, true);
    workflow.band = DiagWorkflowBandNfc;
    workflow.identity.present = true;
    workflow.identity.uid_size = 7u;
    workflow.identity.cascade_count = 2u;
    memcpy(workflow.identity.uid, "1234567", 7u);
    memcpy(workflow.source_path, "/ext/nfc/card.nfc", sizeof("/ext/nfc/card.nfc"));
    workflow.pending_action = DiagWorkflowActionVerify;
    assert(diag_workflow_test_validate(&workflow));

    workflow.identity.uid_size = 5u;
    assert(!diag_workflow_test_validate(&workflow));
    workflow.identity.uid_size = 7u;
    workflow.identity.cascade_count = 3u;
    assert(!diag_workflow_test_validate(&workflow));
    workflow.identity.cascade_count = 2u;
    memcpy(workflow.source_path, "/ext/nfc/card.rfid", sizeof("/ext/nfc/card.rfid"));
    assert(!diag_workflow_test_validate(&workflow));
}

static void test_valid_lf_and_bounds(void) {
    DiagWorkflow workflow;
    diag_workflow_init(&workflow, false);
    workflow.band = DiagWorkflowBandLf;
    memcpy(workflow.source_path, "/ext/lfrfid/card.rfid", sizeof("/ext/lfrfid/card.rfid"));
    workflow.pending_action = DiagWorkflowActionWriteLf;
    assert(diag_workflow_test_validate(&workflow));

    workflow.identity.present = true;
    workflow.identity.uid_size = 4u;
    workflow.identity.cascade_count = 1u;
    assert(!diag_workflow_test_validate(&workflow));
    memset(&workflow.identity, 0, sizeof(workflow.identity));
    workflow.pending_action = DiagWorkflowActionPicopass;
    assert(diag_workflow_test_validate(&workflow));
    workflow.pending_action = DiagWorkflowActionPicopass + 1u;
    assert(!diag_workflow_test_validate(&workflow));
    workflow.pending_action = DiagWorkflowActionNone;
    memset(workflow.source_path, 'x', sizeof(workflow.source_path));
    assert(!diag_workflow_test_validate(&workflow));
}

static void test_empty_identity_consistency(void) {
    DiagWorkflow workflow;
    diag_workflow_init(&workflow, false);
    workflow.identity.atqa[0] = 1u;
    assert(!diag_workflow_test_validate(&workflow));
    memset(&workflow.identity, 0, sizeof(workflow.identity));
    workflow.identity.present = true;
    assert(!diag_workflow_test_validate(&workflow));
}

static void test_strict_bool_tokens(void) {
    bool value = false;
    assert(diag_workflow_test_parse_bool("true", &value));
    assert(value);
    assert(diag_workflow_test_parse_bool("false", &value));
    assert(!value);
    assert(!diag_workflow_test_parse_bool("TRUE", &value));
    assert(!diag_workflow_test_parse_bool("false ", &value));
    assert(!diag_workflow_test_parse_bool("0", &value));
    assert(!diag_workflow_test_parse_bool("garbage", &value));
    assert(!diag_workflow_test_parse_bool(NULL, &value));
    assert(!diag_workflow_test_parse_bool("true", NULL));
}

int main(void) {
    test_init();
    test_valid_nfc();
    test_valid_lf_and_bounds();
    test_empty_identity_consistency();
    test_strict_bool_tokens();
    puts("diag_workflow tests passed");
    return 0;
}
