#ifndef DIAG_NFC_H
#define DIAG_NFC_H

#include "diag_model.h"

typedef struct DiagNfc DiagNfc;

/* The caller must serialize start/free. Snapshots and cancellation are thread-safe. */
DiagNfc* diag_nfc_alloc(void);
void diag_nfc_free(DiagNfc* instance);

/* Starts one live run; false means that another run is still draining or active. */
bool diag_nfc_start(DiagNfc* instance);
void diag_nfc_cancel(DiagNfc* instance);
bool diag_nfc_is_running(DiagNfc* instance);
void diag_nfc_snapshot(DiagNfc* instance, DiagModel* destination);

/* Deadlines bound waiting, not firmware stop/join of an in-flight RF transaction. */
#define DIAG_NFC_DISCOVERY_TIMEOUT_MS 12000u
#define DIAG_NFC_STAGE_TIMEOUT_MS 2500u

#ifdef DIAG_NFC_TESTING
/* Host-only transport seam. These call the live engine's evidence evaluators;
   they do not simulate RF timing, HAL ownership, or physical card behavior. */
bool diag_nfc_test_identity_a(
    DiagModel* model, const uint8_t* uid, size_t uid_size,
    const uint8_t atqa[2], uint8_t sak);
bool diag_nfc_test_version(
    DiagModel* model, DiagProtocol family, int32_t transport_error,
    const uint8_t* version, size_t version_size,
    const uint8_t* live_uid, size_t live_uid_size);
bool diag_nfc_test_classic_nonce(DiagModel* model, int32_t error, size_t response_size);
void diag_nfc_test_finish_failure(DiagModel* model, bool cancelled, bool discovery);
#endif

#endif
