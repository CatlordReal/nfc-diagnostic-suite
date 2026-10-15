#include "../diag_capabilities.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static DiagModel model_with_identity(DiagProtocol protocol) {
    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    const uint8_t uid[] = {1u, 2u, 3u, 4u};
    assert(diag_model_set_identity(&model, protocol, uid, sizeof(uid)));
    return model;
}

static void test_unknown_and_field_only(void) {
    DiagCapabilities capabilities = diag_capabilities_for(NULL);
    assert(!capabilities.has_identity);
    assert(!capabilities.is_nfc);
    assert(!capabilities.is_lf);
    assert(!capabilities.can_native_write);
    assert(!capabilities.can_magic_write);
    assert(!capabilities.can_emulate);
    assert(capabilities.native_tool[0] == '\0');

    DiagModel model;
    diag_model_init(&model, DiagProvenanceLive);
    assert(diag_model_add_protocol_candidate(&model, DiagProtocolIso14443_3a));
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.has_identity);
    assert(!capabilities.is_nfc);
}

static void test_classic_evidence_gate(void) {
    DiagModel model = model_with_identity(DiagProtocolIso14443_3a);
    assert(diag_model_add_protocol_candidate(&model, DiagProtocolMfClassic));
    DiagCapabilities capabilities = diag_capabilities_for(&model);
    assert(capabilities.has_identity && capabilities.is_nfc);
    assert(!capabilities.classic);
    assert(!capabilities.can_native_write);
    assert(!capabilities.can_magic_write);
    assert(capabilities.can_emulate);
    assert(!capabilities.complete_dump_required);

    assert(diag_model_confirm_protocol(&model, DiagProtocolMfClassic, true));
    capabilities = diag_capabilities_for(&model);
    assert(capabilities.classic);
    assert(capabilities.can_native_write);
    assert(capabilities.can_magic_write);
    assert(capabilities.can_emulate);
    assert(capabilities.complete_dump_required);
    assert(!strcmp(capabilities.native_tool, "NFC / NFC Magic"));

    model = model_with_identity(DiagProtocolMfClassic);
    model.provenance = DiagProvenanceSaved;
    model.recorded_provenance = DiagProvenanceLive;
    capabilities = diag_capabilities_for(&model);
    assert(capabilities.classic && capabilities.can_magic_write);
}

static void test_nfc_feature_mappings(void) {
    DiagModel model = model_with_identity(DiagProtocolMfUltralight);
    model.provenance = DiagProvenanceSaved;
    DiagCapabilities capabilities = diag_capabilities_for(&model);
    assert(capabilities.is_nfc && !capabilities.is_lf);
    assert(capabilities.can_native_write && capabilities.can_emulate);
    assert(capabilities.complete_dump_required);

    model = model_with_identity(DiagProtocolMfDesfire);
    model.provenance = DiagProvenanceSaved;
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(!capabilities.complete_dump_required);

    model = model_with_identity(DiagProtocolFelica);
    model.provenance = DiagProvenanceSaved;
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(capabilities.complete_dump_required);

    model = model_with_identity(DiagProtocolIso14443_3b);
    model.provenance = DiagProvenanceSaved;
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.can_native_write && !capabilities.can_emulate);
}

static void test_live_child_identity_requires_confirmation(void) {
    DiagModel model = model_with_identity(DiagProtocolMfClassic);
    DiagCapabilities capabilities = diag_capabilities_for(&model);
    assert(!capabilities.classic);
    assert(!capabilities.can_native_write);
    assert(!capabilities.can_magic_write);
    assert(capabilities.can_emulate);

    model = model_with_identity(DiagProtocolType4Tag);
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(!capabilities.complete_dump_required);

    assert(diag_model_confirm_protocol(&model, DiagProtocolType4Tag, true));
    capabilities = diag_capabilities_for(&model);
    assert(capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(capabilities.complete_dump_required);
}

static void test_live_confirmed_descendant_mappings(void) {
    DiagModel model = model_with_identity(DiagProtocolIso14443_3a);
    assert(diag_model_confirm_protocol(&model, DiagProtocolMfUltralight, true));
    DiagCapabilities capabilities = diag_capabilities_for(&model);
    assert(capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(capabilities.complete_dump_required);

    model = model_with_identity(DiagProtocolIso14443_3a);
    assert(diag_model_confirm_protocol(&model, DiagProtocolIso14443_4a, true));
    assert(diag_model_confirm_protocol(&model, DiagProtocolType4Tag, true));
    capabilities = diag_capabilities_for(&model);
    assert(capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(capabilities.complete_dump_required);

    model = model_with_identity(DiagProtocolIso14443_3a);
    assert(diag_model_add_protocol_candidate(&model, DiagProtocolType4Tag));
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(!capabilities.complete_dump_required);

    model = model_with_identity(DiagProtocolIso14443_3b);
    assert(diag_model_confirm_protocol(&model, DiagProtocolIso14443_4b, true));
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.can_native_write);
    assert(!capabilities.can_emulate);

    model = model_with_identity(DiagProtocolIso15693_3);
    assert(diag_model_confirm_protocol(&model, DiagProtocolSlix, true));
    capabilities = diag_capabilities_for(&model);
    assert(capabilities.can_native_write);
    assert(capabilities.can_emulate);
    assert(capabilities.complete_dump_required);
}

static void test_lf_exact_protocol(void) {
    DiagModel model = model_with_identity(DiagProtocolLfRfid);
    assert(diag_model_set_product_metadata(&model, "EM4100", ""));
    DiagCapabilities capabilities = diag_capabilities_for(&model);
    assert(capabilities.has_identity && capabilities.is_lf && !capabilities.is_nfc);
    assert(capabilities.can_native_write);
    assert(!capabilities.can_magic_write);
    assert(capabilities.can_emulate);
    assert(!capabilities.complete_dump_required);
    assert(!strcmp(capabilities.native_tool, "125 kHz RFID"));

    assert(diag_model_set_product_metadata(&model, "Unknown LF", ""));
    capabilities = diag_capabilities_for(&model);
    assert(!capabilities.can_native_write);
    assert(!capabilities.can_emulate);
}

static bool contains(const unsigned* actions, size_t count, unsigned action) {
    for(size_t i = 0u; i < count; ++i) {
        if(actions[i] == action) return true;
    }
    return false;
}

static void test_unknown_actions(void) {
    DiagCapabilities capabilities = diag_capabilities_for(NULL);
    unsigned actions[16];
    const size_t count = diag_capabilities_workflow_actions(
        capabilities, 0u, false, false, false, actions, 16u);
    assert(contains(actions, count, DiagCapabilityActionGuide));
    assert(contains(actions, count, DiagCapabilityActionReaderTests));
    assert(contains(actions, count, DiagCapabilityActionSourceNfc));
    assert(contains(actions, count, DiagCapabilityActionSourceLf));
    assert(contains(actions, count, DiagCapabilityActionPicopass));
    assert(!contains(actions, count, DiagCapabilityActionFindCard));
    assert(!contains(actions, count, DiagCapabilityActionReadNfc));
    assert(!contains(actions, count, DiagCapabilityActionWriteNfc));
    assert(!contains(actions, count, DiagCapabilityActionWriteLf));
}

static void test_lf_actions_hide_nfc(void) {
    DiagModel model = model_with_identity(DiagProtocolLfRfid);
    assert(diag_model_set_product_metadata(&model, "H10301", ""));
    const DiagCapabilities capabilities = diag_capabilities_for(&model);
    unsigned actions[16];
    const size_t count = diag_capabilities_workflow_actions(
        capabilities, 2u, true, true, true, actions, 16u);
    assert(contains(actions, count, DiagCapabilityActionFindCard));
    assert(contains(actions, count, DiagCapabilityActionReadLf));
    assert(contains(actions, count, DiagCapabilityActionSourceLf));
    assert(contains(actions, count, DiagCapabilityActionWriteLf));
    assert(contains(actions, count, DiagCapabilityActionVerify));
    assert(!contains(actions, count, DiagCapabilityActionReadNfc));
    assert(!contains(actions, count, DiagCapabilityActionSourceNfc));
    assert(!contains(actions, count, DiagCapabilityActionMfkey));
    assert(!contains(actions, count, DiagCapabilityActionPicopass));
    assert(contains(actions, count, DiagCapabilityActionNonceLibrary));
}

static void test_desfire_actions(void) {
    const DiagCapabilities capabilities =
        diag_capabilities_for(&(DiagModel){0});
    assert(!capabilities.has_identity);

    DiagModel model = model_with_identity(DiagProtocolMfDesfire);
    const DiagCapabilities desfire = diag_capabilities_for(&model);
    unsigned actions[16];
    const size_t count = diag_capabilities_workflow_actions(
        desfire, 1u, true, true, false, actions, 16u);
    assert(contains(actions, count, DiagCapabilityActionReadNfc));
    assert(contains(actions, count, DiagCapabilityActionSourceNfc));
    assert(contains(actions, count, DiagCapabilityActionVerify));
    assert(!contains(actions, count, DiagCapabilityActionWriteNfc));
    assert(!contains(actions, count, DiagCapabilityActionCaptureClassic));
    assert(!contains(actions, count, DiagCapabilityActionMfkey));
    assert(!contains(actions, count, DiagCapabilityActionNonceLibrary));
}

static void test_classic_actions(void) {
    DiagModel model = model_with_identity(DiagProtocolIso14443_3a);
    assert(diag_model_confirm_protocol(&model, DiagProtocolMfClassic, true));
    const DiagCapabilities capabilities = diag_capabilities_for(&model);
    unsigned actions[16];
    const size_t count = diag_capabilities_workflow_actions(
        capabilities, 1u, true, true, false, actions, 16u);
    assert(contains(actions, count, DiagCapabilityActionCaptureClassic));
    assert(!contains(actions, count, DiagCapabilityActionMfkey));
    assert(contains(actions, count, DiagCapabilityActionWriteNfc));
    assert(contains(actions, count, DiagCapabilityActionNonceLibrary));

    const size_t with_nonces = diag_capabilities_workflow_actions(
        capabilities, 1u, true, true, true, actions, 16u);
    assert(contains(actions, with_nonces, DiagCapabilityActionMfkey));
}

static void test_source_does_not_grant_capabilities_and_bounds(void) {
    const DiagCapabilities capabilities = diag_capabilities_for(NULL);
    unsigned actions[16];
    const size_t count = diag_capabilities_workflow_actions(
        capabilities, 0u, false, true, false, actions, 16u);
    assert(contains(actions, count, DiagCapabilityActionReadNfc));
    assert(contains(actions, count, DiagCapabilityActionReadLf));
    assert(contains(actions, count, DiagCapabilityActionVerify));
    assert(!contains(actions, count, DiagCapabilityActionWriteNfc));
    assert(!contains(actions, count, DiagCapabilityActionWriteLf));

    unsigned bounded[4] = {99u, 99u, 99u, 99u};
    const size_t bounded_count = diag_capabilities_workflow_actions(
        capabilities, 0u, true, true, true, bounded, 3u);
    assert(bounded_count == 3u);
    assert(bounded[3] == 99u);
    assert(diag_capabilities_workflow_actions(
               capabilities, 0u, true, true, true, NULL, 16u) == 0u);
}

int main(void) {
    test_unknown_and_field_only();
    test_classic_evidence_gate();
    test_nfc_feature_mappings();
    test_live_child_identity_requires_confirmation();
    test_live_confirmed_descendant_mappings();
    test_lf_exact_protocol();
    test_unknown_actions();
    test_lf_actions_hide_nfc();
    test_desfire_actions();
    test_classic_actions();
    test_source_does_not_grant_capabilities_and_bounds();
    puts("diag_capabilities tests passed");
    return 0;
}
