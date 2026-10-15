#ifndef DIAG_LF_H
#define DIAG_LF_H

#include "diag_model.h"

typedef enum {
    DiagLfModeCard,
    DiagLfModeReader,
    DiagLfModeReaderBoth,
} DiagLfMode;

typedef struct {
    DiagLfMode mode;
    uint32_t elapsed_ms;
    uint32_t sample_period_ms;
    uint32_t samples_total;
    uint32_t field_present_samples;
    uint32_t field_absent_samples;
    uint32_t frequency_hz_min;
    uint32_t frequency_hz_max;
    uint32_t frequency_hz_last;
    uint32_t nfc_field_present_samples;
    uint32_t nfc_field_absent_samples;
    bool decoded;
    bool field_seen;
    bool nfc_field_seen;
    bool timed_out;
    bool cancelled;
} DiagLfStats;

typedef struct DiagLf DiagLf;

/* Caller serializes start/free. Snapshot and cancellation are thread-safe. */
DiagLf* diag_lf_alloc(void);
void diag_lf_free(DiagLf* instance);
bool diag_lf_start(DiagLf* instance, DiagLfMode mode);
void diag_lf_cancel(DiagLf* instance);
bool diag_lf_is_running(DiagLf* instance);
void diag_lf_snapshot(DiagLf* instance, DiagModel* model, DiagLfStats* stats);

#define DIAG_LF_TIMEOUT_MS 25000u
#define DIAG_LF_FIELD_SAMPLE_MS 100u

#ifdef DIAG_LF_TESTING
/* Host seam calls production evidence/stat evaluators. It proves no physical RF behavior. */
bool diag_lf_test_decode(
    DiagModel* model,
    DiagLfStats* stats,
    const char* native_protocol_name,
    const uint8_t* decoded_data,
    size_t decoded_size,
    bool native_read_done);
bool diag_lf_test_sample(
    DiagLfStats* stats,
    bool lf_present,
    uint32_t lf_counter_frequency_hz,
    bool nfc_sampled,
    bool nfc_present);
void diag_lf_test_finish(
    DiagModel* model, DiagLfStats* stats, bool cancelled, bool deadline_reached);
#endif

#endif
