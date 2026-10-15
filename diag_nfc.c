#include "diag_nfc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DIAG_BIT(protocol) (1ul << (unsigned)(protocol))

/* These are application errors, never invented firmware status codes. */
typedef enum {
    DiagAppErrorDeadline = 1,
    DiagAppErrorCancelled,
    DiagAppErrorIdentityChanged,
    DiagAppErrorInvalidResponse,
    DiagAppErrorNoIdentity,
    DiagAppErrorUnsupportedUid,
} DiagAppError;

/* The native SDK uses one-byte protocol enums. Copy the bounded scanner result
   into an application-owned bit mask before its callback returns. */
static bool diag_nfc_scanner_candidates(
    const uint8_t* protocols, size_t count, uint32_t* candidates) {
    if(!candidates) return false;
    *candidates = 0;
    if(!protocols || count == 0 || count > DIAG_NFC_PROTOCOL_COUNT) return false;
    uint32_t result = 0;
    for(size_t index = 0; index < count; ++index) {
        if(protocols[index] >= DIAG_NFC_PROTOCOL_COUNT) return false;
        result |= DIAG_BIT(protocols[index]);
    }
    *candidates = result;
    return true;
}

static bool diag_nfc_evidence_uid_same(
    const DiagIdentity* selected, const uint8_t* uid, size_t size) {
    return selected && selected->present && uid && size > 0 &&
           size <= DIAG_MAX_ISO_A_UID_BYTES && size == selected->uid_size &&
           memcmp(uid, selected->uid, size) == 0;
}

static bool diag_nfc_evidence_volatile(const DiagIdentity* selected) {
    return selected && selected->present &&
           ((selected->protocol == DiagProtocolIso14443_3a &&
             selected->uid_size == 4 && selected->uid[0] == 0x08) ||
            selected->protocol == DiagProtocolIso14443_3b);
}

static uint32_t diag_nfc_evidence_a_candidates(uint8_t sak, size_t uid_size) {
    uint32_t candidates = 0;
    if(sak & 0x20) candidates |= DIAG_BIT(DiagProtocolIso14443_4a);
    if(sak == 0x08 || sak == 0x18 || sak == 0x09) {
        candidates |= DIAG_BIT(DiagProtocolMfClassic);
    }
    if(sak == 0 && uid_size == 7) candidates |= DIAG_BIT(DiagProtocolMfUltralight);
    return candidates;
}

static bool diag_nfc_evidence_identity_a(
    DiagModel* model, const uint8_t* uid, size_t size, const uint8_t atqa[2], uint8_t sak) {
    if(!model || !atqa || (size != 4 && size != 7 && size != 10) || !uid) return false;
    if(!diag_model_set_identity(model, DiagProtocolIso14443_3a, uid, size) ||
       !diag_model_set_iso_a_identity(model, uid, size, atqa, sak)) return false;
    uint32_t candidates = diag_nfc_evidence_a_candidates(sak, size);
    for(unsigned protocol = 0; protocol < DIAG_NFC_PROTOCOL_COUNT; ++protocol) {
        if(candidates & DIAG_BIT(protocol)) diag_model_add_protocol_candidate(model, (DiagProtocol)protocol);
    }
    diag_model_confirm_protocol(model, DiagProtocolIso14443_3a, true);
    diag_model_mark_stage_success(model, DiagStageIdentityRead);
    return true;
}

static int32_t diag_nfc_evidence_version(
    const DiagIdentity* selected, DiagProtocol family,
    const uint8_t* version, size_t size, const uint8_t* live_uid, size_t uid_size) {
    if(!version) return DiagAppErrorInvalidResponse;
    if(family == DiagProtocolMfUltralight) {
        if(size != 8 || version[1] != 0x04 || (version[2] != 0x03 && version[2] != 0x04)) {
            return DiagAppErrorInvalidResponse;
        }
    } else {
        uint8_t family_code = family == DiagProtocolMfDesfire ? 1 :
                              family == DiagProtocolMfPlus ? 2 :
                              family == DiagProtocolNtag4xx ? 4 : 0;
        if(!family_code || (size != 28 && !(family == DiagProtocolNtag4xx && size == 29)) ||
           version[0] != 0x04 || (version[1] & 0x0f) != family_code) {
            return DiagAppErrorInvalidResponse;
        }
        live_uid = version + 14;
        uid_size = 7;
    }
    if(!diag_nfc_evidence_uid_same(selected, live_uid, uid_size) &&
       !diag_nfc_evidence_volatile(selected)) {
        return DiagAppErrorIdentityChanged;
    }
    return 0;
}

static bool diag_nfc_evidence_classic_nonce(int32_t error, size_t size) {
    /* API 87.1: Iso14443_3aErrorWrongCrc is 6, because this nonce has no CRC. */
    return error == 6 && size == 4;
}

static void diag_nfc_evidence_failure(DiagModel* model, const char* domain, int32_t code) {
    diag_model_set_error(model, domain, code);
    model->run_succeeded = false;
}

#ifdef DIAG_NFC_TESTING
bool diag_nfc_test_scanner_candidates(
    const uint8_t* protocols, size_t count, uint32_t* candidates) {
    return diag_nfc_scanner_candidates(protocols, count, candidates);
}

bool diag_nfc_test_identity_a(
    DiagModel* model, const uint8_t* uid, size_t size, const uint8_t atqa[2], uint8_t sak) {
    return diag_nfc_evidence_identity_a(model, uid, size, atqa, sak);
}

bool diag_nfc_test_version(
    DiagModel* model, DiagProtocol family, int32_t transport_error,
    const uint8_t* version, size_t size, const uint8_t* live_uid, size_t uid_size) {
    if(!model) return false;
    if(transport_error) {
        diag_model_add_log(model, DiagLogWarning, DiagStageMetadataRead, "Version transport failed");
        return false;
    }
    int32_t verdict = diag_nfc_evidence_version(&model->identity, family, version, size, live_uid, uid_size);
    if(verdict) {
        if(verdict == DiagAppErrorIdentityChanged) {
            diag_nfc_evidence_failure(model, "app.identity", verdict);
        }
        return false;
    }
    diag_model_confirm_protocol(model, family, true);
    if(diag_nfc_evidence_volatile(&model->identity)) {
        diag_model_add_log(model, DiagLogWarning, DiagStageMetadataRead,
                           "Random/volatile UID: physical-card correlation unavailable");
    }
    diag_model_mark_stage_success(model, DiagStageMetadataRead);
    return true;
}

bool diag_nfc_test_classic_nonce(DiagModel* model, int32_t error, size_t size) {
    if(!model || !diag_nfc_evidence_classic_nonce(error, size)) return false;
    return diag_model_confirm_protocol(model, DiagProtocolMfClassic, true);
}

void diag_nfc_test_finish_failure(DiagModel* model, bool cancelled, bool discovery) {
    diag_nfc_evidence_failure(model, cancelled ? "app.cancelled" :
                              discovery ? "app.discovery_deadline" : "app.stage_deadline",
                              cancelled ? DiagAppErrorCancelled : DiagAppErrorDeadline);
}
#else
#include "diag_build.h"

#include <furi.h>
#include <furi_hal_rtc.h>
#include <furi_hal_nfc.h>
#include <nfc/nfc.h>
#include <nfc/nfc_scanner.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>
#include <nfc/protocols/iso14443_3b/iso14443_3b_poller.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_poller.h>
#include <nfc/protocols/iso14443_4b/iso14443_4b_poller.h>
#include <nfc/protocols/iso15693_3/iso15693_3_poller.h>
#include <nfc/protocols/felica/felica_poller.h>
#include <nfc/protocols/st25tb/st25tb_poller.h>
#include <nfc/protocols/mf_ultralight/mf_ultralight_poller.h>
#include <nfc/protocols/mf_desfire/mf_desfire_poller.h>
#include <nfc/protocols/mf_plus/mf_plus_poller.h>
#include <toolbox/version.h>

#define TAG "NfcDiag"
#define DIAG_FLAG_DONE (1u << 0)
#define DIAG_FLAG_CANCEL (1u << 1)
#define DIAG_ALL_FLAGS (DIAG_FLAG_DONE | DIAG_FLAG_CANCEL)

_Static_assert(Iso14443_3aErrorWrongCrc == 6, "Update Classic evidence for this SDK");
_Static_assert(NfcProtocolNum == DIAG_NFC_PROTOCOL_COUNT, "Update protocol coverage for this SDK");
_Static_assert(sizeof(NfcProtocol) == sizeof(uint8_t), "Update scanner enum decoding for this SDK ABI");
_Static_assert((int)NfcProtocolIso14443_3a == (int)DiagProtocolIso14443_3a &&
               (int)NfcProtocolIso14443_3b == (int)DiagProtocolIso14443_3b &&
               (int)NfcProtocolIso14443_4a == (int)DiagProtocolIso14443_4a &&
               (int)NfcProtocolIso14443_4b == (int)DiagProtocolIso14443_4b &&
               (int)NfcProtocolIso15693_3 == (int)DiagProtocolIso15693_3 &&
               (int)NfcProtocolFelica == (int)DiagProtocolFelica &&
               (int)NfcProtocolMfUltralight == (int)DiagProtocolMfUltralight &&
               (int)NfcProtocolMfClassic == (int)DiagProtocolMfClassic &&
               (int)NfcProtocolMfPlus == (int)DiagProtocolMfPlus &&
               (int)NfcProtocolMfDesfire == (int)DiagProtocolMfDesfire &&
               (int)NfcProtocolSlix == (int)DiagProtocolSlix &&
               (int)NfcProtocolSt25tb == (int)DiagProtocolSt25tb &&
               (int)NfcProtocolNtag4xx == (int)DiagProtocolNtag4xx &&
               (int)NfcProtocolType4Tag == (int)DiagProtocolType4Tag &&
               (int)NfcProtocolEmv == (int)DiagProtocolEmv, "Update protocol mapping for this SDK");

typedef enum {
    DiagOperationIdentityA,
    DiagOperationIdentityB,
    DiagOperationIdentityV,
    DiagOperationIdentityF,
    DiagOperationIdentitySt,
    DiagOperationIso4A,
    DiagOperationIso4B,
    DiagOperationClassic,
    DiagOperationUlVersion,
    DiagOperationDesfireVersion,
    DiagOperationPlusVersion,
    DiagOperationNtagVersion,
    DiagOperationType4,
    DiagOperationEmv,
} DiagOperation;

typedef struct {
    bool received;
    bool success;
    bool identity_changed;
    bool correlation_unavailable;
    const char* error_domain;
    int32_t error_code;
    uint32_t candidates;
    uint32_t confirmed;
    uint8_t uid[DIAG_MAX_ISO_A_UID_BYTES];
    size_t uid_size;
    Iso14443_3aData iso_a;
    char product[DIAG_PRODUCT_CAPACITY];
    char version[DIAG_PRODUCT_CAPACITY];
    char detail[DIAG_LOG_MESSAGE_CAPACITY];
} DiagRfResult;

struct DiagNfc {
    FuriMutex* mutex;
    FuriEventFlag* events;
    FuriThread* worker;
    DiagModel model;
    bool running;
    bool worker_started;
    uint32_t started_tick;

    /* Only the worker allocates, starts, stops and frees NFC objects. */
    Nfc* nfc;
    NfcPoller* poller;
    DiagOperation operation;
    DiagRfResult result;
    uint32_t scanner_candidates;
    size_t scanner_count;
    bool scanner_invalid;
    DiagIdentity selected;

    /* Callback-owned working data, allocated and freed by the worker. */
    Iso14443_3bData* iso_b;
    FelicaData* felica;
    BitBuffer* tx;
    BitBuffer* rx;
};

static uint32_t diag_nfc_elapsed(const DiagNfc* instance) {
    uint32_t ticks = furi_get_tick() - instance->started_tick;
    return (uint32_t)(((uint64_t)ticks * 1000u) / furi_kernel_get_tick_frequency());
}

static bool diag_nfc_cancelled(DiagNfc* instance) {
    return (furi_event_flag_get(instance->events) & DIAG_FLAG_CANCEL) != 0;
}

static void diag_nfc_log(
    DiagNfc* instance,
    DiagLogLevel level,
    DiagStage stage,
    const char* message) {
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_add_log_at(&instance->model, level, stage, diag_nfc_elapsed(instance), message);
    furi_mutex_release(instance->mutex);
#ifdef DIAG_USB_LOG
    FURI_LOG_I(TAG, "%s", message);
#endif
}

static bool diag_nfc_domain_is(const char* domain, const char* prefix) {
    return strncmp(domain, prefix, strlen(prefix)) == 0;
}

static const char* diag_nfc_error_label(const char* domain, int32_t code) {
    if(diag_nfc_domain_is(domain, "app.")) {
        switch(code) {
        case DiagAppErrorDeadline: return "Wait deadline expired";
        case DiagAppErrorCancelled: return "Cancelled";
        case DiagAppErrorIdentityChanged: return "Identifier changed";
        case DiagAppErrorInvalidResponse: return "Unexpected response";
        case DiagAppErrorNoIdentity: return "No identity read";
        case DiagAppErrorUnsupportedUid: return "Unsupported UID";
        default: return "Application error";
        }
    }
    if(diag_nfc_domain_is(domain, "furi_hal_nfc")) {
        switch(code) {
        case FuriHalNfcErrorBusy: return "NFC hardware busy";
        case FuriHalNfcErrorCommunication: return "Hardware communication error";
        case FuriHalNfcErrorOscillator: return "Oscillator did not start";
        case FuriHalNfcErrorCommunicationTimeout: return "Hardware timeout";
        case FuriHalNfcErrorBufferOverflow: return "Receive buffer overflow";
        case FuriHalNfcErrorIncompleteFrame: return "Incomplete frame";
        case FuriHalNfcErrorDataFormat: return "Invalid frame format";
        default: return "Unclassified hardware error";
        }
    }
    if(diag_nfc_domain_is(domain, "iso14443_3a") ||
       diag_nfc_domain_is(domain, "iso14443_3b") || diag_nfc_domain_is(domain, "st25tb")) {
        /* These three pinned SDK enums share the activation error values. */
        _Static_assert(Iso14443_3bErrorTimeout == 7 && St25tbErrorTimeout == 7 &&
                       Iso14443_3aErrorTimeout == 7 && Iso14443_3bErrorWrongCrc == 6 &&
                       St25tbErrorWrongCrc == 6, "Update activation error labels");
        switch(code) {
        case Iso14443_3aErrorNone: return "Failure event supplied no error";
        case Iso14443_3aErrorNotPresent: return "No card response";
        case Iso14443_3aErrorColResFailed: return "Collision resolution failed";
        case Iso14443_3aErrorBufferOverflow: return "Receive buffer overflow";
        case Iso14443_3aErrorCommunication: return "Communication error";
        case Iso14443_3aErrorFieldOff: return "RF field off";
        case Iso14443_3aErrorWrongCrc: return "Wrong CRC";
        case Iso14443_3aErrorTimeout: return "Response timeout";
        default: return "Unclassified activation error";
        }
    }
    if(diag_nfc_domain_is(domain, "iso14443_4a") ||
       diag_nfc_domain_is(domain, "iso14443_4b")) {
        _Static_assert((int)Iso14443_4aErrorTimeout == (int)Iso14443_4bErrorTimeout &&
                       (int)Iso14443_4aErrorProtocol == (int)Iso14443_4bErrorProtocol,
                       "Update ISO4 error labels");
        switch(code) {
        case Iso14443_4aErrorNone: return "Failure event supplied no error";
        case Iso14443_4aErrorNotPresent: return "No card response";
        case Iso14443_4aErrorProtocol: return "Protocol error";
        case Iso14443_4aErrorTimeout: return "Response timeout";
        default: return "Unclassified ISO4 error";
        }
    }
    if(diag_nfc_domain_is(domain, "iso15693_3")) {
        switch(code) {
        case Iso15693_3ErrorNotPresent: return "No card response";
        case Iso15693_3ErrorBufferEmpty: return "Empty response";
        case Iso15693_3ErrorBufferOverflow: return "Receive buffer overflow";
        case Iso15693_3ErrorFieldOff: return "RF field off";
        case Iso15693_3ErrorWrongCrc: return "Wrong CRC";
        case Iso15693_3ErrorTimeout: return "Response timeout";
        case Iso15693_3ErrorFormat: return "Invalid response format";
        case Iso15693_3ErrorNotSupported: return "Command unsupported";
        case Iso15693_3ErrorUidMismatch: return "Identifier changed";
        default: return "Unclassified ISO15693 error";
        }
    }
    if(diag_nfc_domain_is(domain, "felica")) {
        switch(code) {
        case FelicaErrorNotPresent: return "No card response";
        case FelicaErrorColResFailed: return "Collision resolution failed";
        case FelicaErrorBufferOverflow: return "Receive buffer overflow";
        case FelicaErrorCommunication: return "Communication error";
        case FelicaErrorFieldOff: return "RF field off";
        case FelicaErrorWrongCrc: return "Wrong CRC";
        case FelicaErrorProtocol: return "Protocol error";
        case FelicaErrorTimeout: return "Response timeout";
        case FelicaErrorFeatureUnsupported: return "Feature unsupported";
        default: return "Unclassified FeliCa error";
        }
    }
    if(diag_nfc_domain_is(domain, "mf_ultralight")) {
        switch(code) {
        case MfUltralightErrorNotPresent: return "No card response";
        case MfUltralightErrorProtocol: return "Protocol error";
        case MfUltralightErrorAuth: return "Authentication status reported";
        case MfUltralightErrorTimeout: return "Response timeout";
        default: return "Unclassified Ultralight error";
        }
    }
    if(diag_nfc_domain_is(domain, "mf_desfire")) {
        switch(code) {
        case MfDesfireErrorNotPresent: return "No card response";
        case MfDesfireErrorProtocol: return "Protocol error";
        case MfDesfireErrorTimeout: return "Response timeout";
        case MfDesfireErrorAuthentication: return "Authentication status reported";
        case MfDesfireErrorCommandNotSupported: return "Command unsupported";
        default: return "Unclassified DESFire error";
        }
    }
    if(diag_nfc_domain_is(domain, "mf_plus")) {
        switch(code) {
        case MfPlusErrorNotPresent: return "No card response";
        case MfPlusErrorProtocol: return "Protocol error";
        case MfPlusErrorAuth: return "Authentication status reported";
        case MfPlusErrorPartialRead: return "Partial response";
        case MfPlusErrorTimeout: return "Response timeout";
        default: return "Unclassified Plus error";
        }
    }
    if(strstr(domain, ".status")) {
        if(code == 0x6a82) return "Application not found";
        if(code == 0x6d00 || code == 0x1c) return "Command unsupported";
        if(code == 0x6982 || code == 0x9d) return "Access denied";
        return "Card returned status";
    }
    return "Unclassified firmware error";
}

static void diag_nfc_error(
    DiagNfc* instance,
    DiagStage stage,
    const char* domain,
    int32_t code,
    bool terminal) {
    char message[DIAG_LOG_MESSAGE_CAPACITY];
    snprintf(message, sizeof(message), "%s: %s error=%ld",
             diag_nfc_error_label(domain, code), domain, (long)code);
    diag_nfc_log(instance, terminal ? DiagLogError : DiagLogWarning, stage, message);
    if(terminal) {
        furi_mutex_acquire(instance->mutex, FuriWaitForever);
        diag_nfc_evidence_failure(&instance->model, domain, code);
        furi_mutex_release(instance->mutex);
    }
}

static void diag_nfc_publish(DiagNfc* instance, const DiagRfResult* result) {
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    instance->result = *result;
    instance->result.received = true;
    furi_mutex_release(instance->mutex);
    furi_event_flag_set(instance->events, DIAG_FLAG_DONE);
}

static bool diag_nfc_uid_matches(DiagNfc* instance, const uint8_t* uid, size_t size) {
    return diag_nfc_evidence_uid_same(&instance->selected, uid, size);
}

static bool diag_nfc_correlate(
    DiagNfc* instance, DiagRfResult* result, const uint8_t* uid, size_t size) {
    if(!uid || size == 0 || size > DIAG_MAX_ISO_A_UID_BYTES) return false;
    if(diag_nfc_evidence_volatile(&instance->selected)) {
        result->correlation_unavailable = true;
        return true;
    }
    return diag_nfc_uid_matches(instance, uid, size);
}

static void diag_nfc_changed(DiagRfResult* result) {
    result->success = false;
    result->identity_changed = true;
    result->error_domain = "app.identity";
    result->error_code = DiagAppErrorIdentityChanged;
    snprintf(result->detail, sizeof(result->detail),
             "UID differs from selected identity; swap/random UID possible; metadata rejected");
}

static bool diag_nfc_version_valid(
    DiagNfc* instance, DiagRfResult* result, DiagProtocol family,
    const void* version, size_t size, const uint8_t* live_uid, size_t uid_size) {
    int32_t verdict = diag_nfc_evidence_version(
        &instance->selected, family, version, size, live_uid, uid_size);
    if(verdict == DiagAppErrorIdentityChanged) {
        diag_nfc_changed(result);
    } else if(verdict) {
        result->success = false;
        result->error_domain = "app.version_family";
        result->error_code = verdict;
    }
    if(verdict == 0 && diag_nfc_evidence_volatile(&instance->selected)) {
        result->correlation_unavailable = true;
        if(family != DiagProtocolMfUltralight && size >= 21) {
            const uint8_t* uid = (const uint8_t*)version + 14;
            snprintf(result->detail, sizeof(result->detail),
                     "GET_VERSION manufacturing UID=%02X%02X%02X%02X%02X%02X%02X; primary observed UID retained",
                     uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]);
        }
    }
    return verdict == 0;
}

static void diag_nfc_copy_uid(DiagRfResult* result, const uint8_t* uid, size_t size) {
    if(uid && size > 0 && size <= sizeof(result->uid)) {
        memcpy(result->uid, uid, size);
        result->uid_size = size;
    } else {
        result->success = false;
        result->error_domain = "app.response";
        result->error_code = DiagAppErrorInvalidResponse;
    }
}

/* Scanner events are copied by value; no scanner-owned array escapes this callback. */
static void diag_nfc_scanner_callback(NfcScannerEvent event, void* context) {
    DiagNfc* instance = context;
    if(event.type != NfcScannerEventTypeDetected || diag_nfc_cancelled(instance)) return;
    uint32_t candidates = 0;
    bool invalid = !diag_nfc_scanner_candidates(
        (const uint8_t*)event.data.protocols, event.data.protocol_num, &candidates);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    instance->scanner_count = event.data.protocol_num;
    instance->scanner_invalid = invalid;
    instance->scanner_candidates = candidates;
    furi_mutex_release(instance->mutex);
    furi_event_flag_set(instance->events, DIAG_FLAG_DONE);
}

static NfcCommand diag_nfc_base_callback(NfcGenericEventEx event, void* context) {
    DiagNfc* instance = context;
    if(diag_nfc_cancelled(instance)) return NfcCommandStop;
    const NfcEvent* parent = event.parent_event_data;
    if(parent->type != NfcEventTypePollerReady) return NfcCommandContinue;
    DiagRfResult result = {.error_domain = "app.response"};
    switch(instance->operation) {
    case DiagOperationIdentityA: {
        result.error_domain = "iso14443_3a";
        result.error_code = iso14443_3a_poller_activate(event.poller, &result.iso_a);
        result.success = result.error_code == Iso14443_3aErrorNone;
        if(result.success) {
            diag_nfc_copy_uid(&result, result.iso_a.uid, result.iso_a.uid_len);
            result.confirmed = DIAG_BIT(DiagProtocolIso14443_3a);
            result.candidates = diag_nfc_evidence_a_candidates(result.iso_a.sak, result.iso_a.uid_len);
            snprintf(result.detail, sizeof(result.detail), "ISO A activation: UID/ATQA/SAK; cascade count derived");
        }
        break;
    }
    case DiagOperationIdentityB: {
        result.error_domain = "iso14443_3b";
        result.error_code = iso14443_3b_poller_activate(event.poller, instance->iso_b);
        result.success = result.error_code == Iso14443_3bErrorNone;
        if(result.success) {
            size_t size = 0;
            const uint8_t* uid = iso14443_3b_get_uid(instance->iso_b, &size);
            diag_nfc_copy_uid(&result, uid, size);
            result.confirmed = DIAG_BIT(DiagProtocolIso14443_3b);
            if(iso14443_3b_supports_iso14443_4(instance->iso_b)) {
                result.candidates |= DIAG_BIT(DiagProtocolIso14443_4b);
            }
            snprintf(result.detail, sizeof(result.detail), "ISO B activation; identifier is PUPI (may be random)");
            snprintf(result.product, sizeof(result.product), "ISO14443-B activation");
            snprintf(result.version, sizeof(result.version), "frame=%u; FWT=%lu fc (declared)",
                     iso14443_3b_get_frame_size_max(instance->iso_b),
                     (unsigned long)iso14443_3b_get_fwt_fc_max(instance->iso_b));
        }
        break;
    }
    case DiagOperationIdentityV:
        result.error_domain = "iso15693_3.inventory";
        result.error_code = iso15693_3_poller_inventory(event.poller, result.uid);
        result.success = result.error_code == Iso15693_3ErrorNone;
        if(result.success) {
            result.uid_size = ISO15693_3_UID_SIZE;
            result.confirmed = DIAG_BIT(DiagProtocolIso15693_3);
            snprintf(result.detail, sizeof(result.detail), "ISO15693 inventory UID; no block read or password command");
        }
        break;
    case DiagOperationIdentityF:
        result.error_domain = "felica";
        result.error_code = felica_poller_activate(event.poller, instance->felica);
        result.success = result.error_code == FelicaErrorNone;
        if(result.success) {
            result.uid_size = FELICA_IDM_SIZE;
            memcpy(result.uid, instance->felica->idm.data, result.uid_size);
            result.confirmed = DIAG_BIT(DiagProtocolFelica);
            snprintf(result.detail, sizeof(result.detail), "FeliCa polling response IDm/PMm; no services read");
            snprintf(result.product, sizeof(result.product), "FeliCa polling identification");
            const uint8_t* pmm = instance->felica->pmm.data;
            snprintf(result.version, sizeof(result.version), "PMm=%02X%02X%02X%02X%02X%02X%02X%02X",
                     pmm[0], pmm[1], pmm[2], pmm[3], pmm[4], pmm[5], pmm[6], pmm[7]);
        }
        break;
    case DiagOperationIdentitySt: {
        uint8_t chip_id;
        result.error_domain = "st25tb.initiate";
        result.error_code = st25tb_poller_initiate(event.poller, &chip_id);
        if(result.error_code == St25tbErrorNone && !diag_nfc_cancelled(instance)) {
            result.error_domain = "st25tb.select";
            result.error_code = st25tb_poller_select(event.poller, &chip_id);
        }
        if(result.error_code == St25tbErrorNone && !diag_nfc_cancelled(instance)) {
            result.error_domain = "st25tb.get_uid";
            result.error_code = st25tb_poller_get_uid(event.poller, result.uid);
            result.success = result.error_code == St25tbErrorNone;
            if(result.success) {
                result.uid_size = ST25TB_UID_SIZE;
                result.confirmed = DIAG_BIT(DiagProtocolSt25tb);
                snprintf(result.detail, sizeof(result.detail), "ST25TB Initiate/Select/GetUID succeeded; no blocks read");
            }
        }
        break;
    }
    default:
        result.error_code = DiagAppErrorInvalidResponse;
        break;
    }
    diag_nfc_publish(instance, &result);
    return NfcCommandStop;
}

/* This callback runs only the explicitly named read-version command. The leaf
   protocol's authentication/write-capable state machine is never started. */
static NfcCommand diag_nfc_version_callback(NfcGenericEventEx event, void* context) {
    DiagNfc* instance = context;
    if(diag_nfc_cancelled(instance)) return NfcCommandStop;
    DiagRfResult result = {.error_domain = "app.response"};
    if(instance->operation == DiagOperationUlVersion) {
        const Iso14443_3aPollerEvent* parent = event.parent_event_data;
        if(parent->type != Iso14443_3aPollerEventTypeReady) {
            result.error_domain = "iso14443_3a";
            result.error_code = parent->data->error;
        } else {
            MfUltralightPageReadCommandData pages = {0};
            result.error_domain = "mf_ultralight.uid_read";
            result.error_code = mf_ultralight_poller_read_page(event.poller, 0, &pages);
            if(result.error_code == MfUltralightErrorNone) {
                uint8_t uid[7];
                memcpy(uid, pages.page[0].data, 3);
                memcpy(uid + 3, pages.page[1].data, 4);
                if(!diag_nfc_uid_matches(instance, uid, sizeof(uid))) {
                    diag_nfc_changed(&result);
                } else if(!diag_nfc_cancelled(instance)) {
                    MfUltralightVersion version = {0};
                    result.error_domain = "mf_ultralight.version";
                    result.error_code = mf_ultralight_poller_read_version(event.poller, &version);
                    result.success = result.error_code == MfUltralightErrorNone;
                    if(result.success && diag_nfc_version_valid(instance, &result,
                        DiagProtocolMfUltralight, &version, sizeof(version), uid, sizeof(uid))) {
                        result.confirmed = DIAG_BIT(DiagProtocolMfUltralight);
                        snprintf(result.product, sizeof(result.product), "Ultralight/NTAG GET_VERSION type=%02X", version.prod_type);
                        const uint8_t* bytes = (const uint8_t*)&version;
                        snprintf(result.version, sizeof(result.version), "%02X %02X %02X %02X %02X %02X %02X %02X", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]);
                    }
                }
            }
        }
    } else {
        const Iso14443_4aPollerEvent* parent = event.parent_event_data;
        if(parent->type != Iso14443_4aPollerEventTypeReady) {
            result.error_domain = "iso14443_4a";
            result.error_code = parent->data->error;
        } else if(instance->operation == DiagOperationDesfireVersion) {
            MfDesfireVersion version = {0};
            result.error_domain = "mf_desfire.version";
            result.error_code = mf_desfire_poller_read_version(event.poller, &version);
            result.success = result.error_code == MfDesfireErrorNone;
            if(result.success && diag_nfc_version_valid(instance, &result,
                DiagProtocolMfDesfire, &version, sizeof(version), NULL, 0)) {
                result.confirmed = DIAG_BIT(DiagProtocolMfDesfire);
                snprintf(result.product, sizeof(result.product), "MIFARE DESFire GET_VERSION");
                snprintf(result.version, sizeof(result.version), "HW %02X.%02X storage=%02X; SW %02X.%02X", version.hw_major, version.hw_minor, version.hw_storage, version.sw_major, version.sw_minor);
            }
        } else {
            MfPlusVersion version = {0};
            result.error_domain = "mf_plus.version";
            result.error_code = mf_plus_poller_read_version(event.poller, &version);
            result.success = result.error_code == MfPlusErrorNone;
            if(result.success && diag_nfc_version_valid(instance, &result,
                DiagProtocolMfPlus, &version, sizeof(version), NULL, 0)) {
                result.confirmed = DIAG_BIT(DiagProtocolMfPlus);
                snprintf(result.product, sizeof(result.product), "MIFARE Plus GET_VERSION");
                snprintf(result.version, sizeof(result.version), "HW %02X.%02X storage=%02X; SW %02X.%02X", version.hw_major, version.hw_minor, version.hw_storage, version.sw_major, version.sw_minor);
            }
        }
    }
    diag_nfc_publish(instance, &result);
    return NfcCommandStop;
}

/* Bounded BER-TLV traversal for a PPSE directory response. */
static bool diag_nfc_contains_aid(const uint8_t* bytes, size_t size, unsigned depth) {
    if(depth > 6) return false;
    size_t offset = 0;
    while(offset < size) {
        uint8_t tag = bytes[offset++];
        if((tag & 0x1f) == 0x1f) {
            unsigned count = 0;
            do {
                if(offset == size || ++count > 3) return false;
            } while(bytes[offset++] & 0x80);
        }
        if(offset == size) return false;
        size_t length = bytes[offset++];
        if(length & 0x80) {
            unsigned count = length & 0x7f;
            if(count == 0 || count > 2 || count > size - offset) return false;
            length = 0;
            while(count--) length = (length << 8) | bytes[offset++];
        }
        if(length > size - offset) return false;
        if(tag == 0x4f && length >= 5 && length <= 16) return true;
        if((tag & 0x20) && diag_nfc_contains_aid(bytes + offset, length, depth + 1)) return true;
        offset += length;
    }
    return false;
}

/* NTAG4xx has no exported read-version function in API 87.1. Use its documented
   ISO-wrapped GET_VERSION command, at most four native response frames. */
static void diag_nfc_ntag_version(
    DiagNfc* instance,
    Iso14443_4aPoller* poller,
    DiagRfResult* result) {
    uint8_t version[29] = {0};
    size_t used = 0;
    uint8_t command = 0x60;
    result->error_domain = "iso14443_4a.ntag_version";
    for(unsigned frame = 0; frame < 4 && !diag_nfc_cancelled(instance); ++frame) {
        uint8_t request[] = {0x90, command, 0, 0, 0};
        bit_buffer_copy_bytes(instance->tx, request, sizeof(request));
        result->error_code = iso14443_4a_poller_send_block(poller, instance->tx, instance->rx);
        if(result->error_code != Iso14443_4aErrorNone) return;
        size_t size = bit_buffer_get_size_bytes(instance->rx);
        const uint8_t* response = bit_buffer_get_data(instance->rx);
        if(size < 2 || response[size - 2] != 0x91 || size - 2 > sizeof(version) - used) {
            result->error_domain = "app.ntag_response";
            result->error_code = DiagAppErrorInvalidResponse;
            return;
        }
        memcpy(version + used, response, size - 2);
        used += size - 2;
        uint8_t status = response[size - 1];
        if(status == 0xaf) {
            command = 0xaf;
            continue;
        }
        if(status != 0) {
            result->error_domain = "ntag4xx.status";
            result->error_code = status;
            return;
        }
        if(!diag_nfc_version_valid(instance, result, DiagProtocolNtag4xx,
                                   version, used, NULL, 0)) return;
        result->success = true;
        result->confirmed = DIAG_BIT(DiagProtocolNtag4xx);
        snprintf(result->product, sizeof(result->product), "NTAG4xx GET_VERSION");
        snprintf(result->version, sizeof(result->version), "HW %02X.%02X storage=%02X; SW %02X.%02X", version[3], version[4], version[5], version[10], version[11]);
        return;
    }
    result->error_domain = "app.ntag_frame_limit";
    result->error_code = DiagAppErrorInvalidResponse;
}

static NfcCommand diag_nfc_ready_callback(NfcGenericEvent event, void* context) {
    DiagNfc* instance = context;
    if(diag_nfc_cancelled(instance)) return NfcCommandStop;
    DiagRfResult result = {.error_domain = "app.response"};
    const uint8_t* uid = NULL;
    size_t size = 0;
    if(instance->operation == DiagOperationClassic) {
        const Iso14443_3aPollerEvent* parent = event.event_data;
        result.error_domain = "iso14443_3a";
        if(parent->type != Iso14443_3aPollerEventTypeReady) {
            result.error_code = parent->data->error;
            diag_nfc_publish(instance, &result);
            return NfcCommandStop;
        }
        const Iso14443_3aData* data = nfc_poller_get_data(instance->poller);
        uid = iso14443_3a_get_uid(data, &size);
        if(!diag_nfc_correlate(instance, &result, uid, size)) {
            diag_nfc_changed(&result);
        } else {
            const uint8_t request[] = {0x60, 0x00};
            bit_buffer_copy_bytes(instance->tx, request, sizeof(request));
            result.error_code = iso14443_3a_poller_send_standard_frame(
                event.instance, instance->tx, instance->rx, 60000);
            if(diag_nfc_evidence_classic_nonce(result.error_code, bit_buffer_get_size_bytes(instance->rx))) {
                result.success = true;
                result.confirmed = DIAG_BIT(DiagProtocolMfClassic);
                snprintf(result.detail, sizeof(result.detail), "Classic-compatible AUTH-A block0 nonce; iso14443_3a=%ld, 4 bytes", (long)result.error_code);
                snprintf(result.product, sizeof(result.product), "Classic-compatible; capacity inferred");
                snprintf(result.version, sizeof(result.version), "SAK=%02X hint=%s; size unverified", data->sak, data->sak == 0x18 ? "4K" : data->sak == 0x08 ? "1K" : "unknown");
            } else if(result.error_code == Iso14443_3aErrorNone) {
                result.error_domain = "app.classic_nonce";
                result.error_code = DiagAppErrorInvalidResponse;
            }
        }
        diag_nfc_publish(instance, &result);
        return NfcCommandStop;
    }
    if(instance->operation == DiagOperationIso4B) {
        const Iso14443_4bPollerEvent* parent = event.event_data;
        result.error_domain = "iso14443_4b";
        result.success = parent->type == Iso14443_4bPollerEventTypeReady;
        if(result.success) {
            const Iso14443_4bData* data = nfc_poller_get_data(instance->poller);
            uid = iso14443_4b_get_uid(data, &size);
            result.confirmed = DIAG_BIT(DiagProtocolIso14443_4b);
        } else {
            result.error_code = parent->data->error;
        }
    } else {
        const Iso14443_4aPollerEvent* parent = event.event_data;
        result.error_domain = "iso14443_4a";
        result.success = parent->type == Iso14443_4aPollerEventTypeReady;
        if(result.success) {
            const Iso14443_4aData* data = nfc_poller_get_data(instance->poller);
            uid = iso14443_4a_get_uid(data, &size);
            result.confirmed = DIAG_BIT(DiagProtocolIso14443_4a);
        } else {
            result.error_code = parent->data->error;
        }
    }
    if(result.success && !diag_nfc_correlate(instance, &result, uid, size)) {
        diag_nfc_changed(&result);
    }
    if(result.success && instance->operation == DiagOperationNtagVersion) {
        result.success = false;
        result.confirmed = 0;
        diag_nfc_ntag_version(instance, event.instance, &result);
    } else if(result.success && (instance->operation == DiagOperationType4 ||
                                instance->operation == DiagOperationEmv)) {
        static const uint8_t ndef_select[] = {
            0x00, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00};
        static const uint8_t ppse_select[] = {
            0x00, 0xa4, 0x04, 0x00, 0x0e, '2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1', 0x00};
        bool emv = instance->operation == DiagOperationEmv;
        bit_buffer_copy_bytes(instance->tx, emv ? ppse_select : ndef_select, emv ? sizeof(ppse_select) : sizeof(ndef_select));
        result.success = false;
        result.confirmed = 0;
        result.error_code = iso14443_4a_poller_send_block(event.instance, instance->tx, instance->rx);
        if(result.error_code == Iso14443_4aErrorNone) {
            size_t length = bit_buffer_get_size_bytes(instance->rx);
            const uint8_t* bytes = bit_buffer_get_data(instance->rx);
            result.error_domain = emv ? "emv.ppse.status" : "type4.select.status";
            if(length >= 2) {
                result.error_code = ((uint16_t)bytes[length - 2] << 8) | bytes[length - 1];
                result.success = result.error_code == 0x9000;
                if(result.success && emv) {
                    result.success = length > 2 && bytes[0] == 0x6f &&
                                     diag_nfc_contains_aid(bytes, length - 2, 0);
                    if(!result.success) {
                        result.error_domain = "app.ppse_directory";
                        result.error_code = DiagAppErrorInvalidResponse;
                    }
                }
                if(result.success) {
                    result.confirmed = DIAG_BIT(emv ? DiagProtocolEmv : DiagProtocolType4Tag);
                    snprintf(result.detail, sizeof(result.detail), "%s SELECT status=9000%s", emv ? "PPSE" : "NDEF app", emv ? "; valid AID in directory" : "");
                }
            } else {
                result.error_domain = "app.apdu_response";
                result.error_code = DiagAppErrorInvalidResponse;
            }
        }
    }
    diag_nfc_publish(instance, &result);
    return NfcCommandStop;
}

static bool diag_nfc_wait(DiagNfc* instance, uint32_t timeout_ms) {
    uint32_t started = furi_get_tick();
    uint32_t timeout = furi_ms_to_ticks(timeout_ms);
    while((furi_get_tick() - started) < timeout) {
        uint32_t flags = furi_event_flag_wait(
            instance->events, DIAG_ALL_FLAGS, FuriFlagWaitAny | FuriFlagNoClear,
            furi_ms_to_ticks(25));
        if(diag_nfc_cancelled(instance)) return false;
        if((flags & FuriFlagError) == 0 && (flags & DIAG_FLAG_DONE)) return true;
    }
    return false;
}

static bool diag_nfc_probe(
    DiagNfc* instance,
    NfcProtocol protocol,
    DiagOperation operation,
    const char* label,
    bool extended,
    DiagRfResult* result) {
    memset(result, 0, sizeof(*result));
    if(diag_nfc_cancelled(instance)) return false;
    DiagStage stage = operation <= DiagOperationIdentitySt ? DiagStageIdentityRead :
                      operation == DiagOperationUlVersion ||
                      operation == DiagOperationDesfireVersion ||
                      operation == DiagOperationPlusVersion ||
                      operation == DiagOperationNtagVersion ? DiagStageMetadataRead :
                      DiagStageProtocolRead;
    diag_nfc_log(instance, DiagLogInfo, stage, label);
    instance->operation = operation;
    memset(&instance->result, 0, sizeof(instance->result));
    furi_event_flag_clear(instance->events, DIAG_FLAG_DONE);
    instance->poller = nfc_poller_alloc(instance->nfc, protocol);
    if(extended) {
        bool version = operation == DiagOperationUlVersion ||
                       operation == DiagOperationDesfireVersion || operation == DiagOperationPlusVersion;
        nfc_poller_start_ex(instance->poller, version ? diag_nfc_version_callback : diag_nfc_base_callback, instance);
    } else {
        nfc_poller_start(instance->poller, diag_nfc_ready_callback, instance);
    }
    bool done = diag_nfc_wait(instance, DIAG_NFC_STAGE_TIMEOUT_MS);
    /* Never stop in the NFC callback: stop joins that callback's worker. */
    nfc_poller_stop(instance->poller);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    if(done) *result = instance->result;
    furi_mutex_release(instance->mutex);
    nfc_poller_free(instance->poller);
    instance->poller = NULL;
    if(!done) {
        result->error_domain = diag_nfc_cancelled(instance) ? "app.cancelled" : "app.stage_deadline";
        result->error_code = diag_nfc_cancelled(instance) ? DiagAppErrorCancelled : DiagAppErrorDeadline;
    }
    if(!result->success && !diag_nfc_cancelled(instance)) {
        if(result->detail[0]) {
            diag_nfc_log(instance, DiagLogWarning, stage, result->detail);
        }
        diag_nfc_error(instance, stage, result->error_domain, result->error_code, result->identity_changed);
    }
    return result->success && !diag_nfc_cancelled(instance);
}

static void diag_nfc_apply(DiagNfc* instance, const DiagRfResult* result, DiagStage stage) {
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    for(unsigned protocol = 0; protocol < DIAG_NFC_PROTOCOL_COUNT; ++protocol) {
        if(result->candidates & DIAG_BIT(protocol)) {
            diag_model_add_protocol_candidate(&instance->model, (DiagProtocol)protocol);
        }
        if(result->confirmed & DIAG_BIT(protocol)) {
            diag_model_confirm_protocol(&instance->model, (DiagProtocol)protocol, true);
        }
    }
    if(result->product[0]) {
        diag_model_set_product_metadata(&instance->model, result->product, result->version);
    }
    diag_model_mark_stage_success(&instance->model, stage);
    furi_mutex_release(instance->mutex);
    for(unsigned protocol = 0; protocol < DIAG_NFC_PROTOCOL_COUNT; ++protocol) {
        if(result->confirmed & DIAG_BIT(protocol)) {
            char message[DIAG_LOG_MESSAGE_CAPACITY];
            snprintf(message, sizeof(message), "Confirmed %s: independent command response",
                     diag_protocol_name((DiagProtocol)protocol));
            diag_nfc_log(instance, DiagLogSuccess, stage, message);
        }
    }
    if(result->detail[0]) diag_nfc_log(instance, DiagLogSuccess, stage, result->detail);
    if(result->product[0]) diag_nfc_log(instance, DiagLogSuccess, stage, result->product);
    if(result->correlation_unavailable) {
        diag_nfc_log(instance, DiagLogWarning, stage,
                     "Volatile UID: evidence is current activation; physical-card correlation unavailable");
    }
}

static bool diag_nfc_optional(
    DiagNfc* instance,
    NfcProtocol protocol,
    DiagOperation operation,
    const char* label,
    bool extended,
    DiagStage success_stage) {
    DiagRfResult result;
    if(diag_nfc_probe(instance, protocol, operation, label, extended, &result)) {
        diag_nfc_apply(instance, &result, success_stage);
    }
    return !result.identity_changed && !diag_nfc_cancelled(instance);
}

static bool diag_nfc_diagnose_a(DiagNfc* instance, const DiagRfResult* identity) {
    bool iso4 = (identity->iso_a.sak & 0x20) != 0;
    bool classic_candidate = (identity->candidates & DIAG_BIT(DiagProtocolMfClassic)) ||
                             (instance->scanner_candidates & DIAG_BIT(DiagProtocolMfClassic));
    if(classic_candidate) {
        diag_nfc_log(instance, DiagLogInfo, DiagStageProtocolRead,
                     "Classic probe: AUTH-A block0 nonce only; no key, auth completion or recovery");
        if(!diag_nfc_optional(instance, NfcProtocolIso14443_3a, DiagOperationClassic,
                              "Probe Classic-compatible nonce response", false,
                              DiagStageProtocolRead)) return false;
    }
    if(!iso4) {
        if(identity->iso_a.sak == 0 && identity->uid_size == 7) {
            if(!diag_nfc_optional(instance, NfcProtocolMfUltralight, DiagOperationUlVersion,
                                  "Read Ultralight/NTAG UID page0 then GET_VERSION", true,
                                  DiagStageMetadataRead)) return false;
        }
        return true;
    }
    DiagRfResult result;
    if(!diag_nfc_probe(instance, NfcProtocolIso14443_4a, DiagOperationIso4A,
                       "Activate ISO14443-4A; read ATS and check selected UID", false, &result)) {
        return !result.identity_changed && !diag_nfc_cancelled(instance);
    }
    diag_nfc_apply(instance, &result, DiagStageProtocolRead);
    if(!diag_nfc_optional(instance, NfcProtocolMfDesfire, DiagOperationDesfireVersion,
                          "Read DESFire GET_VERSION only; check version UID", true,
                          DiagStageMetadataRead)) return false;
    if(!diag_nfc_optional(instance, NfcProtocolMfPlus, DiagOperationPlusVersion,
                          "Read Plus GET_VERSION only; ATS/SAK never confirm Plus", true,
                          DiagStageMetadataRead)) return false;
    if(!diag_nfc_optional(instance, NfcProtocolIso14443_4a, DiagOperationNtagVersion,
                          "Read NTAG4xx wrapped GET_VERSION; check selected UID", false,
                          DiagStageMetadataRead)) return false;
    if(!diag_nfc_optional(instance, NfcProtocolIso14443_4a, DiagOperationType4,
                          "SELECT NDEF application; no NDEF file read", false,
                          DiagStageProtocolRead)) return false;
    return diag_nfc_optional(instance, NfcProtocolIso14443_4a, DiagOperationEmv,
                             "SELECT PPSE directory; no payment application read", false,
                             DiagStageProtocolRead);
}

static NfcProtocol diag_nfc_root(NfcProtocol protocol) {
    NfcProtocol parent;
    while((parent = nfc_protocol_get_parent(protocol)) != NfcProtocolInvalid) protocol = parent;
    return protocol;
}

static int32_t diag_nfc_worker(void* context) {
    DiagNfc* instance = context;
    bool completed = false;
    /* nfc_alloc asserts on HAL acquisition failure. The loader serializes normal
       NFC apps; this preflight also returns an explicit hardware/busy error.
       The SDK provides no atomic checked-allocation API, so the loader's normal
       exclusive-app contract is still required between preflight and allocation. */
    FuriHalNfcError readiness = furi_hal_nfc_is_hal_ready();
    if(readiness != FuriHalNfcErrorNone) {
        diag_nfc_error(instance, DiagStageNone, "furi_hal_nfc.ready", readiness, true);
        furi_mutex_acquire(instance->mutex, FuriWaitForever);
        instance->running = false;
        furi_mutex_release(instance->mutex);
        return 0;
    }
    instance->nfc = nfc_alloc();
    instance->iso_b = iso14443_3b_alloc();
    instance->felica = felica_alloc();
    instance->tx = bit_buffer_alloc(256);
    instance->rx = bit_buffer_alloc(256);

    NfcScanner* scanner = nfc_scanner_alloc(instance->nfc);
    diag_nfc_log(instance, DiagLogInfo, DiagStageFieldStarted,
                 "Scanner session started; private RF/anticollision sub-stages unavailable");
    diag_nfc_log(instance, DiagLogInfo, DiagStageFieldStarted,
                 "Automatic scanner probes all 15 protocols; read-only discovery includes Classic nonce");
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_mark_stage_success(&instance->model, DiagStageFieldStarted);
    furi_mutex_release(instance->mutex);
    nfc_scanner_start(scanner, diag_nfc_scanner_callback, instance);
    bool found = diag_nfc_wait(instance, DIAG_NFC_DISCOVERY_TIMEOUT_MS);
    if(!found && !diag_nfc_cancelled(instance)) {
        diag_nfc_log(instance, DiagLogWarning, DiagStageFieldStarted,
                     "Discovery wait deadline 12000ms; stopping and joining firmware scanner");
    }
    nfc_scanner_stop(scanner);
    nfc_scanner_free(scanner);
    if(diag_nfc_cancelled(instance)) goto finish;
    if(!found) {
        diag_nfc_error(instance, DiagStageFieldStarted, "app.discovery_deadline",
                       DiagAppErrorDeadline, true);
        goto finish;
    }
    furi_event_flag_clear(instance->events, DIAG_FLAG_DONE);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_mark_stage_success(&instance->model, DiagStageTechnologyDetected);
    for(unsigned protocol = 0; protocol < DIAG_NFC_PROTOCOL_COUNT; ++protocol) {
        if(instance->scanner_candidates & DIAG_BIT(protocol)) {
            diag_model_add_protocol_candidate(&instance->model, (DiagProtocol)protocol);
        }
    }
    furi_mutex_release(instance->mutex);
    if(instance->scanner_invalid) {
        diag_nfc_log(instance, DiagLogWarning, DiagStageTechnologyDetected,
                     "Invalid scanner list rejected; independent identity probes follow");
    } else {
        diag_nfc_log(instance, DiagLogSuccess, DiagStageTechnologyDetected,
                     "Scanner candidates copied; confirmation requires independent command response");
    }

    static const NfcProtocol base_protocols[] = {
        NfcProtocolIso14443_3a, NfcProtocolIso14443_3b, NfcProtocolIso15693_3,
        NfcProtocolFelica, NfcProtocolSt25tb};
    static const DiagOperation base_operations[] = {
        DiagOperationIdentityA, DiagOperationIdentityB, DiagOperationIdentityV,
        DiagOperationIdentityF, DiagOperationIdentitySt};
    static const char* base_labels[] = {
        "Select ISO A and read UID/ATQA/SAK", "Select ISO B and read PUPI",
        "ISO15693 inventory UID only", "FeliCa polling IDm/PMm only",
        "ST25TB Initiate/Select/GetUID only"};
    NfcProtocol preferred = NfcProtocolInvalid;
    for(unsigned protocol = 0; protocol < DIAG_NFC_PROTOCOL_COUNT; ++protocol) {
        if(instance->scanner_candidates & DIAG_BIT(protocol)) {
            preferred = diag_nfc_root((NfcProtocol)protocol);
            break;
        }
    }
    DiagRfResult identity = {0};
    NfcProtocol selected_protocol = NfcProtocolInvalid;
    /* First retry the scanner's technology; otherwise choose first independent
       valid identity. Results from other cards/technologies are never merged. */
    for(unsigned pass = 0; pass < 2 && selected_protocol == NfcProtocolInvalid; ++pass) {
        for(unsigned index = 0; index < COUNT_OF(base_protocols); ++index) {
            NfcProtocol protocol = base_protocols[index];
            if((pass == 0 && protocol != preferred) || (pass == 1 && protocol == preferred)) continue;
            if(diag_nfc_probe(instance, protocol, base_operations[index], base_labels[index], true, &identity)) {
                selected_protocol = protocol;
                break;
            }
            if(diag_nfc_cancelled(instance)) goto finish;
        }
    }
    if(selected_protocol == NfcProtocolInvalid) {
        diag_nfc_error(instance, DiagStageTechnologyDetected, "app.no_identity",
                       DiagAppErrorNoIdentity, true);
        goto finish;
    }
    instance->selected = (DiagIdentity){.present = true, .protocol = (DiagProtocol)selected_protocol,
                                       .uid_size = identity.uid_size};
    memcpy(instance->selected.uid, identity.uid, identity.uid_size);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_set_identity(&instance->model, (DiagProtocol)selected_protocol,
                            identity.uid, identity.uid_size);
    if(selected_protocol == NfcProtocolIso14443_3a) {
        diag_nfc_evidence_identity_a(&instance->model, identity.uid, identity.uid_size,
                                     identity.iso_a.atqa, identity.iso_a.sak);
    }
    instance->selected = instance->model.identity;
    furi_mutex_release(instance->mutex);
    diag_nfc_apply(instance, &identity, DiagStageIdentityRead);
    if(selected_protocol == NfcProtocolIso14443_3a) {
        if(!diag_nfc_diagnose_a(instance, &identity)) goto finish;
    } else if(selected_protocol == NfcProtocolIso14443_3b &&
              (identity.candidates & DIAG_BIT(DiagProtocolIso14443_4b))) {
        if(!diag_nfc_optional(instance, NfcProtocolIso14443_4b, DiagOperationIso4B,
                              "Activate ISO14443-4B; verify selected PUPI", false,
                              DiagStageProtocolRead)) goto finish;
    } else if(selected_protocol == NfcProtocolIso15693_3) {
        diag_nfc_log(instance, DiagLogInfo, DiagStageIdentityRead,
                     "SLIX scanner classification remains candidate; UID alone does not confirm family");
    }
    completed = true;

finish:
    if(diag_nfc_cancelled(instance)) {
        diag_nfc_error(instance, DiagStageNone, "app.cancelled", DiagAppErrorCancelled, true);
        completed = false;
    }
    /* All callback workers have been stopped/joined before their buffers die. */
    bit_buffer_free(instance->tx);
    bit_buffer_free(instance->rx);
    felica_free(instance->felica);
    iso14443_3b_free(instance->iso_b);
    nfc_free(instance->nfc);
    instance->tx = NULL;
    instance->rx = NULL;
    instance->felica = NULL;
    instance->iso_b = NULL;
    instance->nfc = NULL;
    if(completed) {
        diag_nfc_log(instance, DiagLogSuccess, DiagStageComplete,
                     "Diagnostic complete; unsupported optional probes remain logged, candidates unconfirmed");
    } else {
        diag_nfc_log(instance, DiagLogInfo, DiagStageNone,
                     "Diagnostic stopped; last successful stage preserved; RF worker joined");
    }
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    instance->model.run_succeeded = completed;
    if(completed) diag_model_mark_stage_success(&instance->model, DiagStageComplete);
    instance->running = false;
    furi_mutex_release(instance->mutex);
    return 0;
}

DiagNfc* diag_nfc_alloc(void) {
    DiagNfc* instance = calloc(1, sizeof(DiagNfc));
    furi_check(instance);
    instance->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    instance->events = furi_event_flag_alloc();
    instance->worker = furi_thread_alloc_ex("NfcDiagWorker", 4096, diag_nfc_worker, instance);
    diag_model_init(&instance->model, DiagProvenanceLive);
    return instance;
}

void diag_nfc_free(DiagNfc* instance) {
    if(!instance) return;
    diag_nfc_cancel(instance);
    if(instance->worker_started) furi_thread_join(instance->worker);
    furi_thread_free(instance->worker);
    furi_event_flag_free(instance->events);
    furi_mutex_free(instance->mutex);
    free(instance);
}

bool diag_nfc_start(DiagNfc* instance) {
    furi_check(instance);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    bool busy = instance->running;
    furi_mutex_release(instance->mutex);
    if(busy) return false;
    if(instance->worker_started) furi_thread_join(instance->worker);
    furi_event_flag_clear(instance->events, DIAG_ALL_FLAGS);
    DateTime rtc;
    furi_hal_rtc_get_datetime(&rtc);
    char timestamp[DIAG_TIMESTAMP_CAPACITY];
    snprintf(timestamp, sizeof(timestamp), "%04u-%02u-%02uT%02u:%02u:%02u", rtc.year,
             rtc.month, rtc.day, rtc.hour, rtc.minute, rtc.second);
    char runtime[DIAG_RUNTIME_VERSION_CAPACITY];
    snprintf(runtime, sizeof(runtime), "%.14s %.12s", version_get_version(NULL),
             version_get_githash(NULL));
    instance->started_tick = furi_get_tick();
    memset(&instance->selected, 0, sizeof(instance->selected));
    instance->scanner_candidates = 0;
    instance->scanner_count = 0;
    instance->scanner_invalid = false;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_init(&instance->model, DiagProvenanceLive);
    diag_model_set_timestamp(&instance->model, timestamp);
    diag_model_set_runtime_provenance(&instance->model, DIAG_FIRMWARE_BUILD, runtime);
    instance->running = true;
    furi_mutex_release(instance->mutex);
    instance->worker_started = true;
    furi_thread_start(instance->worker);
    return true;
}

void diag_nfc_cancel(DiagNfc* instance) {
    if(instance) furi_event_flag_set(instance->events, DIAG_FLAG_CANCEL);
}

bool diag_nfc_is_running(DiagNfc* instance) {
    furi_check(instance);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    bool running = instance->running;
    furi_mutex_release(instance->mutex);
    return running;
}

void diag_nfc_snapshot(DiagNfc* instance, DiagModel* destination) {
    furi_check(instance);
    furi_check(destination);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    *destination = instance->model;
    furi_mutex_release(instance->mutex);
}

bool diag_nfc_read_model(
    DiagNfc* instance, DiagModelReadCallback callback, void* context) {
    if(!instance || !callback) return false;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    callback(&instance->model, context);
    furi_mutex_release(instance->mutex);
    return true;
}
#endif /* DIAG_NFC_TESTING */
