#include "diag_capabilities.h"

#include <string.h>

/* Momentum applications/main/nfc/helpers/protocol_support feature tables. */
static const DiagProtocolSupport diag_nfc_features[DIAG_NFC_PROTOCOL_COUNT] = {
    [DiagProtocolIso14443_3a] = {.emulate = true},
    [DiagProtocolIso14443_3b] = {0},
    [DiagProtocolIso14443_4a] = {.emulate = true},
    [DiagProtocolIso14443_4b] = {0},
    [DiagProtocolIso15693_3] = {.write = true, .emulate = true, .full_data = true},
    [DiagProtocolFelica] = {.emulate = true, .full_data = true},
    [DiagProtocolMfUltralight] = {.write = true, .emulate = true, .full_data = true},
    [DiagProtocolMfClassic] = {.write = true, .emulate = true, .full_data = true},
    [DiagProtocolMfPlus] = {.emulate = true},
    [DiagProtocolMfDesfire] = {.emulate = true},
    [DiagProtocolSlix] = {.write = true, .emulate = true, .full_data = true},
    [DiagProtocolSt25tb] = {0},
    [DiagProtocolNtag4xx] = {.emulate = true},
    [DiagProtocolType4Tag] = {.write = true, .emulate = true, .full_data = true},
    [DiagProtocolEmv] = {0},
};

const DiagProtocolSupport* diag_protocol_support(DiagProtocol protocol) {
    return (unsigned)protocol < DIAG_NFC_PROTOCOL_COUNT ? &diag_nfc_features[protocol] : NULL;
}

/* Every protocol registered by Momentum's current lfrfid_protocols table has write_data. */
static const char* const diag_lf_writable_protocols[] = {
    "EM4100",
    "EM4100/32",
    "EM4100/16",
    "Electra",
    "H10301",
    "Idteck",
    "Indala26",
    "Indala224",
    "IoProxXSF",
    "AWID",
    "FDX-A",
    "FDX-B",
    "HIDProx",
    "HIDExt",
    "Pyramid",
    "Viking",
    "Jablotron",
    "Paradox",
    "PAC/Stanley",
    "Keri",
    "Gallagher",
    "Nexwatch",
    "Radio Key",
    "GProxII",
    "Noralsy",
    "InstaFob",
};

static bool diag_identity_valid(const DiagIdentity* identity) {
    if(!identity || !identity->present || (unsigned)identity->protocol >= DIAG_PROTOCOL_COUNT)
        return false;
    if(identity->protocol == DiagProtocolLfRfid)
        return identity->uid_size > 0u && identity->uid_size <= DIAG_MAX_UID_BYTES;
    return identity->uid_size > 0u && identity->uid_size <= DIAG_MAX_ISO_A_UID_BYTES;
}

static bool diag_bounded_equal(const char* value, size_t capacity, const char* expected) {
    const size_t expected_size = strlen(expected);
    if(expected_size >= capacity) return false;
    return !memcmp(value, expected, expected_size) && value[expected_size] == '\0';
}

static bool diag_lf_protocol_is_writable(const char* name) {
    for(size_t i = 0u;
        i < sizeof(diag_lf_writable_protocols) / sizeof(diag_lf_writable_protocols[0]);
        ++i) {
        if(diag_bounded_equal(name, DIAG_PRODUCT_CAPACITY, diag_lf_writable_protocols[i]))
            return true;
    }
    return false;
}

static bool diag_protocol_confirmed(const DiagModel* model, DiagProtocol protocol) {
    return (model->protocols_confirmed & (UINT32_C(1) << (unsigned)protocol)) != 0u;
}

static DiagProtocol diag_effective_nfc_protocol(const DiagModel* model) {
    const DiagProtocol identity = model->identity.protocol;
    if(model->provenance == DiagProvenanceSaved) return identity;
    if(identity == DiagProtocolIso14443_3b &&
       diag_protocol_confirmed(model, DiagProtocolIso14443_4b)) {
        return DiagProtocolIso14443_4b;
    }
    if(identity == DiagProtocolIso15693_3 &&
       diag_protocol_confirmed(model, DiagProtocolSlix)) {
        return DiagProtocolSlix;
    }
    if(identity != DiagProtocolIso14443_3a && identity != DiagProtocolIso14443_4a) {
        if(diag_protocol_confirmed(model, identity)) return identity;
        switch(identity) {
        case DiagProtocolIso14443_4b:
            return DiagProtocolIso14443_3b;
        case DiagProtocolSlix:
            return DiagProtocolIso15693_3;
        case DiagProtocolMfUltralight:
        case DiagProtocolMfClassic:
            return DiagProtocolIso14443_3a;
        case DiagProtocolMfPlus:
        case DiagProtocolMfDesfire:
        case DiagProtocolNtag4xx:
        case DiagProtocolType4Tag:
        case DiagProtocolEmv:
            return DiagProtocolIso14443_4a;
        default:
            return identity;
        }
    }

    /* Live diagnosis retains the selected base identity and records verified
       descendants separately. Later application-level evidence is strongest. */
    static const DiagProtocol descendants[] = {
        DiagProtocolEmv,
        DiagProtocolType4Tag,
        DiagProtocolNtag4xx,
        DiagProtocolMfDesfire,
        DiagProtocolMfPlus,
        DiagProtocolMfClassic,
        DiagProtocolMfUltralight,
        DiagProtocolIso14443_4a,
    };
    for(size_t i = 0u; i < sizeof(descendants) / sizeof(descendants[0]); ++i) {
        if(diag_protocol_confirmed(model, descendants[i])) return descendants[i];
    }
    return identity;
}

DiagCapabilities diag_capabilities_for(const DiagModel* model) {
    DiagCapabilities result = {
        .limitation = "No decoded identity; protocol-specific actions unavailable.",
        .native_tool = "",
    };
    if(!model || !diag_identity_valid(&model->identity)) return result;

    result.has_identity = true;
    if(model->identity.protocol == DiagProtocolLfRfid) {
        result.is_lf = true;
        const bool exact_native_protocol =
            diag_lf_protocol_is_writable(model->metadata.product);
        result.can_native_write = exact_native_protocol;
        result.can_emulate = exact_native_protocol;
        result.native_tool = "125 kHz RFID";
        result.limitation = result.can_native_write ?
            "Native encoding exists; blank-chip compatibility is checked by 125 kHz RFID." :
            "Exact current LF protocol name is required; blank-chip compatibility is not guaranteed.";
        return result;
    }

    result.is_nfc = true;
    result.native_tool = "NFC";
    const bool classic_confirmed =
        (model->identity.protocol == DiagProtocolIso14443_3a ||
         model->identity.protocol == DiagProtocolIso14443_4a ||
         model->identity.protocol == DiagProtocolMfClassic) &&
        diag_protocol_confirmed(model, DiagProtocolMfClassic);
    const bool classic_saved = model->provenance == DiagProvenanceSaved &&
                               model->identity.protocol == DiagProtocolMfClassic;
    result.classic = classic_confirmed || classic_saved;

    DiagProtocol protocol = diag_effective_nfc_protocol(model);
    if((unsigned)protocol >= DIAG_NFC_PROTOCOL_COUNT) return result;
    const DiagProtocolSupport features = diag_nfc_features[protocol];
    result.can_native_write = features.write;
    result.can_magic_write = result.classic;
    result.can_emulate = features.emulate;
    result.complete_dump_required = features.full_data || result.can_magic_write;

    if(result.classic) {
        result.native_tool = "NFC / NFC Magic";
        result.limitation =
            "Writing or full emulation needs a complete MIFARE Classic dump; target access is checked by the native app.";
    } else if(features.write) {
        result.limitation =
            "Native write support still requires a compatible target and complete source data.";
    } else if(features.emulate) {
        result.limitation = features.full_data ?
            "Full emulation requires complete source data." :
            "Momentum supports UID-only emulation for this protocol.";
    } else {
        result.limitation =
            "Momentum's NFC app supports reading this protocol, but exposes no write or emulation feature.";
    }
    return result;
}

static void diag_add_action(
    unsigned action,
    unsigned* actions,
    size_t capacity,
    size_t* count) {
    if(*count < capacity) actions[(*count)++] = action;
}

size_t diag_capabilities_workflow_actions(
    DiagCapabilities capabilities,
    unsigned band,
    bool have_card,
    bool has_source,
    bool has_nonce_pairs,
    unsigned* actions,
    size_t capacity) {
    if(!actions || capacity == 0u) return 0u;
    size_t count = 0u;
    const bool band_unknown = band == 0u;
    const bool band_nfc = band == 1u;
    const bool band_lf = band == 2u;
    const bool can_read = have_card || has_source;

#define DIAG_ADD(action) diag_add_action((action), actions, capacity, &count)
    DIAG_ADD(DiagCapabilityActionGuide);
    if(have_card) DIAG_ADD(DiagCapabilityActionFindCard);
    DIAG_ADD(DiagCapabilityActionReaderTests);
    if(can_read && (band_unknown || band_nfc)) DIAG_ADD(DiagCapabilityActionReadNfc);
    if(can_read && (band_unknown || band_lf)) DIAG_ADD(DiagCapabilityActionReadLf);
    if(band_unknown || band_nfc) DIAG_ADD(DiagCapabilityActionSourceNfc);
    if(band_unknown || band_lf) DIAG_ADD(DiagCapabilityActionSourceLf);
    if(capabilities.classic) DIAG_ADD(DiagCapabilityActionCaptureClassic);
    if(has_nonce_pairs && !band_lf) DIAG_ADD(DiagCapabilityActionMfkey);
    if(has_source && (band_unknown || band_nfc) && capabilities.is_nfc &&
       (capabilities.can_native_write || capabilities.can_magic_write)) {
        DIAG_ADD(DiagCapabilityActionWriteNfc);
    }
    if(has_source && (band_unknown || band_lf) && capabilities.is_lf &&
       capabilities.can_native_write)
        DIAG_ADD(DiagCapabilityActionWriteLf);
    if(has_source) DIAG_ADD(DiagCapabilityActionVerify);
    DIAG_ADD(DiagCapabilityActionSave);
    DIAG_ADD(DiagCapabilityActionNew);
    if(!band_lf && !capabilities.has_identity) DIAG_ADD(DiagCapabilityActionPicopass);
    if(capabilities.classic || has_nonce_pairs) DIAG_ADD(DiagCapabilityActionNonceLibrary);
#undef DIAG_ADD
    return count;
}
