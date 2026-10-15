#include "diag_lf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    DiagLfErrorDeadline = 1,
    DiagLfErrorCancelled,
    DiagLfErrorInvalidDecodedData,
} DiagLfError;

static bool diag_lf_name_valid(const char* name) {
    if(!name) return false;
    size_t length = 0;
    while(length < DIAG_PRODUCT_CAPACITY && name[length]) ++length;
    return length > 0u && length < DIAG_PRODUCT_CAPACITY;
}

static void diag_lf_increment(uint32_t* value) {
    if(*value < UINT32_MAX) ++*value;
}

static bool diag_lf_apply_decode(
    DiagModel* model,
    DiagLfStats* stats,
    const char* native_protocol_name,
    const uint8_t* decoded_data,
    size_t decoded_size,
    bool native_read_done) {
    if(!model || model->provenance != DiagProvenanceLive || !stats || !native_read_done ||
       !diag_lf_name_valid(native_protocol_name) ||
       !decoded_data || decoded_size == 0u || decoded_size > DIAG_MAX_UID_BYTES) {
        return false;
    }
    if(!diag_model_set_identity(
           model, DiagProtocolLfRfid, decoded_data, decoded_size) ||
       !diag_model_set_product_metadata(
           model, native_protocol_name, "Native LFRFIDWorker decoded data")) {
        return false;
    }
    if(!diag_model_confirm_protocol(model, DiagProtocolLfRfid, true)) return false;
    diag_model_mark_stage_success(model, DiagStageIdentityRead);
    diag_model_mark_stage_success(model, DiagStageProtocolRead);
    diag_model_mark_stage_success(model, DiagStageMetadataRead);
    stats->decoded = true;
    return true;
}

static bool diag_lf_apply_sample(
    DiagLfStats* stats,
    bool lf_present,
    uint32_t lf_counter_frequency_hz,
    bool nfc_sampled,
    bool nfc_present) {
    if(!stats ||
       (stats->mode != DiagLfModeReader && stats->mode != DiagLfModeReaderBoth) ||
       (nfc_sampled != (stats->mode == DiagLfModeReaderBoth))) {
        return false;
    }
    diag_lf_increment(&stats->samples_total);
    stats->frequency_hz_last = lf_counter_frequency_hz;
    if(lf_present) {
        diag_lf_increment(&stats->field_present_samples);
        stats->field_seen = true;
        if(stats->frequency_hz_min == 0u ||
           lf_counter_frequency_hz < stats->frequency_hz_min) {
            stats->frequency_hz_min = lf_counter_frequency_hz;
        }
        if(lf_counter_frequency_hz > stats->frequency_hz_max) {
            stats->frequency_hz_max = lf_counter_frequency_hz;
        }
    } else {
        diag_lf_increment(&stats->field_absent_samples);
    }
    if(nfc_sampled) {
        if(nfc_present) {
            diag_lf_increment(&stats->nfc_field_present_samples);
            stats->nfc_field_seen = true;
        } else {
            diag_lf_increment(&stats->nfc_field_absent_samples);
        }
    }
    return true;
}

static void diag_lf_apply_finish(
    DiagModel* model, DiagLfStats* stats, bool cancelled, bool deadline_reached) {
    if(!model || !stats) return;
    stats->cancelled = cancelled;
    stats->timed_out = deadline_reached;
    if(cancelled) {
        diag_model_set_error(model, "app.cancelled", DiagLfErrorCancelled);
    } else if(stats->mode == DiagLfModeCard && deadline_reached && !stats->decoded) {
        diag_model_set_error(model, "app.lf_deadline", DiagLfErrorDeadline);
    } else if(stats->mode != DiagLfModeCard && deadline_reached) {
        diag_model_mark_stage_success(model, DiagStageComplete);
    }
}

#ifdef DIAG_LF_TESTING

bool diag_lf_test_decode(
    DiagModel* model,
    DiagLfStats* stats,
    const char* native_protocol_name,
    const uint8_t* decoded_data,
    size_t decoded_size,
    bool native_read_done) {
    return diag_lf_apply_decode(
        model, stats, native_protocol_name, decoded_data, decoded_size, native_read_done);
}

bool diag_lf_test_sample(
    DiagLfStats* stats,
    bool lf_present,
    uint32_t lf_counter_frequency_hz,
    bool nfc_sampled,
    bool nfc_present) {
    return diag_lf_apply_sample(
        stats, lf_present, lf_counter_frequency_hz, nfc_sampled, nfc_present);
}

void diag_lf_test_finish(
    DiagModel* model, DiagLfStats* stats, bool cancelled, bool deadline_reached) {
    diag_lf_apply_finish(model, stats, cancelled, deadline_reached);
}

#else

#include "diag_build.h"

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_nfc.h>
#include <furi_hal_rfid.h>
#include <lfrfid/lfrfid_worker.h>
#include <lfrfid/protocols/lfrfid_protocols.h>
#include <toolbox/protocols/protocol_dict.h>
#include <toolbox/version.h>

#define DIAG_LF_FLAG_DECODED (1u << 0)
#define DIAG_LF_FLAG_CANCEL  (1u << 1)
#define DIAG_LF_ALL_FLAGS    (DIAG_LF_FLAG_DECODED | DIAG_LF_FLAG_CANCEL)

struct DiagLf {
    FuriMutex* mutex;
    FuriEventFlag* events;
    FuriThread* thread;
    DiagModel model;
    DiagLfStats stats;
    bool running;
    bool thread_started;
    uint32_t started_tick;
    ProtocolId decoded_protocol;
};

static uint32_t diag_lf_elapsed(const DiagLf* instance) {
    uint32_t ticks = furi_get_tick() - instance->started_tick;
    return (uint32_t)(((uint64_t)ticks * 1000u) / furi_kernel_get_tick_frequency());
}

static void diag_lf_log(
    DiagLf* instance, DiagLogLevel level, DiagStage stage, const char* message) {
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_add_log_at(
        &instance->model, level, stage, diag_lf_elapsed(instance), message);
    furi_mutex_release(instance->mutex);
}

static void diag_lf_set_error(
    DiagLf* instance, const char* domain, int32_t code, const char* detail) {
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_set_error(&instance->model, domain, code);
    diag_model_add_log_at(
        &instance->model,
        DiagLogError,
        instance->model.last_successful_stage,
        diag_lf_elapsed(instance),
        detail);
    furi_mutex_release(instance->mutex);
}

static void diag_lf_read_callback(
    LFRFIDWorkerReadResult result, ProtocolId protocol, void* context) {
    DiagLf* instance = context;
    if(result != LFRFIDWorkerReadDone) return;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    instance->decoded_protocol = protocol;
    furi_mutex_release(instance->mutex);
    furi_event_flag_set(instance->events, DIAG_LF_FLAG_DECODED);
}

static bool diag_lf_cancelled(DiagLf* instance) {
    return (furi_event_flag_get(instance->events) & DIAG_LF_FLAG_CANCEL) != 0u;
}

static void diag_lf_finish_running(DiagLf* instance, bool succeeded) {
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    instance->stats.elapsed_ms = diag_lf_elapsed(instance);
    instance->model.run_succeeded = succeeded;
    instance->running = false;
    furi_mutex_release(instance->mutex);
}

static int32_t diag_lf_card_worker(DiagLf* instance) {
    bool decoded = false;
    bool deadline = false;
    ProtocolDict* dict = protocol_dict_alloc(lfrfid_protocols, LFRFIDProtocolMax);
    LFRFIDWorker* worker = lfrfid_worker_alloc(dict);
    lfrfid_worker_start_thread(worker);
    lfrfid_worker_read_start(
        worker, LFRFIDWorkerReadTypeAuto, diag_lf_read_callback, instance);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_mark_stage_success(&instance->model, DiagStageFieldStarted);
    furi_mutex_release(instance->mutex);
    diag_lf_log(
        instance,
        DiagLogInfo,
        DiagStageFieldStarted,
        "Native LF worker scanning all registered ASK/PSK protocols");

    while(!diag_lf_cancelled(instance)) {
        uint32_t remaining = DIAG_LF_TIMEOUT_MS - diag_lf_elapsed(instance);
        if(remaining > DIAG_LF_TIMEOUT_MS) remaining = 0u;
        if(remaining == 0u) {
            deadline = true;
            break;
        }
        uint32_t flags = furi_event_flag_wait(
            instance->events,
            DIAG_LF_ALL_FLAGS,
            FuriFlagWaitAny | FuriFlagNoClear,
            remaining < DIAG_LF_FIELD_SAMPLE_MS ? remaining : DIAG_LF_FIELD_SAMPLE_MS);
        if((flags & FuriFlagError) == 0u && (flags & DIAG_LF_FLAG_DECODED)) {
            decoded = true;
            break;
        }
    }

    lfrfid_worker_stop(worker);
    lfrfid_worker_stop_thread(worker);
    lfrfid_worker_free(worker);

    if(decoded) {
        ProtocolId protocol;
        furi_mutex_acquire(instance->mutex, FuriWaitForever);
        protocol = instance->decoded_protocol;
        furi_mutex_release(instance->mutex);
        if(protocol < 0 || protocol >= (ProtocolId)LFRFIDProtocolMax) {
            diag_lf_set_error(
                instance,
                "app.lf_decode",
                DiagLfErrorInvalidDecodedData,
                "Native LF worker returned invalid protocol ID");
            decoded = false;
        } else {
            size_t data_size = protocol_dict_get_data_size(dict, protocol);
            uint8_t data[DIAG_MAX_UID_BYTES] = {0};
            if(data_size == 0u || data_size > sizeof(data)) {
                diag_lf_set_error(
                    instance,
                    "app.lf_decode",
                    DiagLfErrorInvalidDecodedData,
                    "Native LF decoded data exceeds portable identity capacity");
                decoded = false;
            } else {
                protocol_dict_get_data(dict, protocol, data, data_size);
                const char* name = protocol_dict_get_name(dict, protocol);
                furi_mutex_acquire(instance->mutex, FuriWaitForever);
                decoded = diag_lf_apply_decode(
                    &instance->model,
                    &instance->stats,
                    name,
                    data,
                    data_size,
                    true);
                furi_mutex_release(instance->mutex);
                if(!decoded) {
                    diag_lf_set_error(
                        instance,
                        "app.lf_decode",
                        DiagLfErrorInvalidDecodedData,
                        "Native LF decoded data failed validation");
                } else {
                    diag_lf_log(
                        instance,
                        DiagLogSuccess,
                        DiagStageMetadataRead,
                        "Native LF protocol and decoded bytes recorded; no writes performed");
                }
            }
        }
    }
    protocol_dict_free(dict);

    const bool cancelled = diag_lf_cancelled(instance);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_lf_apply_finish(&instance->model, &instance->stats, cancelled, deadline);
    if(decoded && !cancelled) diag_model_mark_stage_success(&instance->model, DiagStageComplete);
    furi_mutex_release(instance->mutex);
    if(cancelled) {
        diag_lf_log(instance, DiagLogInfo, DiagStageNone, "LF card scan cancelled; worker joined");
    } else if(deadline) {
        diag_lf_log(
            instance,
            DiagLogWarning,
            DiagStageFieldStarted,
            "LF card scan deadline reached without a native protocol decode");
    }
    diag_lf_finish_running(instance, decoded && !cancelled);
    return 0;
}

static void diag_lf_log_field_transition(
    DiagLf* instance, bool lf_present, uint32_t frequency_hz, bool nfc_present) {
    char detail[DIAG_LOG_MESSAGE_CAPACITY];
    if(lf_present) {
        snprintf(
            detail,
            sizeof(detail),
            "LF reader field present; counter frequency=%lu Hz",
            (unsigned long)frequency_hz);
    } else {
        snprintf(
            detail,
            sizeof(detail),
            "LF reader field absent; counter frequency=%lu Hz",
            (unsigned long)frequency_hz);
    }
    diag_lf_log(instance, DiagLogInfo, DiagStageFieldStarted, detail);
    if(instance->stats.mode == DiagLfModeReaderBoth) {
        diag_lf_log(
            instance,
            DiagLogInfo,
            DiagStageFieldStarted,
            nfc_present ? "13.56 MHz NFC reader field present" :
                          "13.56 MHz NFC reader field absent");
    }
}

static int32_t diag_lf_reader_worker(DiagLf* instance) {
    bool nfc_acquired = false;
    bool nfc_started = false;
    bool setup_ok = true;
    const bool sample_nfc = instance->stats.mode == DiagLfModeReaderBoth;
    furi_hal_rfid_field_detect_start();
    if(sample_nfc) {
        FuriHalNfcError error = furi_hal_nfc_acquire();
        if(error == FuriHalNfcErrorNone) {
            nfc_acquired = true;
            error = furi_hal_nfc_field_detect_start();
        }
        if(error == FuriHalNfcErrorNone) {
            nfc_started = true;
        } else {
            setup_ok = false;
            diag_lf_set_error(
                instance, "furi_hal_nfc", error, "NFC reader-field monitor setup failed");
        }
    }
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_mark_stage_success(&instance->model, DiagStageFieldStarted);
    furi_mutex_release(instance->mutex);
    diag_lf_log(
        instance,
        DiagLogInfo,
        DiagStageFieldStarted,
        sample_nfc ? "Passive LF + NFC reader-field sampling started; no RF strength API" :
                     "Passive LF reader-field sampling started; counter frequency in Hz");

    bool have_previous = false;
    bool previous_lf = false;
    bool previous_nfc = false;
    bool deadline = false;
    while(setup_ok && !diag_lf_cancelled(instance)) {
        if(diag_lf_elapsed(instance) >= DIAG_LF_TIMEOUT_MS) {
            deadline = true;
            break;
        }
        uint32_t frequency_hz = 0u;
        bool lf_present = furi_hal_rfid_field_is_present(&frequency_hz);
        bool nfc_present = nfc_started && furi_hal_nfc_field_is_present();
        furi_mutex_acquire(instance->mutex, FuriWaitForever);
        diag_lf_apply_sample(
            &instance->stats,
            lf_present,
            frequency_hz,
            sample_nfc,
            nfc_present);
        instance->stats.elapsed_ms = diag_lf_elapsed(instance);
        furi_mutex_release(instance->mutex);
        if(!have_previous || lf_present != previous_lf ||
           (sample_nfc && nfc_present != previous_nfc)) {
            diag_lf_log_field_transition(instance, lf_present, frequency_hz, nfc_present);
            have_previous = true;
            previous_lf = lf_present;
            previous_nfc = nfc_present;
        }
        furi_event_flag_wait(
            instance->events,
            DIAG_LF_FLAG_CANCEL,
            FuriFlagWaitAny | FuriFlagNoClear,
            DIAG_LF_FIELD_SAMPLE_MS);
    }

    furi_hal_rfid_field_detect_stop();
    if(nfc_started) {
        FuriHalNfcError error = furi_hal_nfc_field_detect_stop();
        if(error != FuriHalNfcErrorNone && setup_ok) {
            setup_ok = false;
            diag_lf_set_error(
                instance, "furi_hal_nfc", error, "NFC reader-field monitor stop failed");
        }
    }
    if(nfc_acquired) {
        FuriHalNfcError error = furi_hal_nfc_release();
        if(error != FuriHalNfcErrorNone && setup_ok) {
            setup_ok = false;
            diag_lf_set_error(
                instance, "furi_hal_nfc", error, "NFC hardware release failed");
        }
    }

    const bool cancelled = diag_lf_cancelled(instance);
    char version[DIAG_VERSION_CAPACITY];
    snprintf(
        version,
        sizeof(version),
        "%lu ms samples; LF counter Hz%s",
        (unsigned long)DIAG_LF_FIELD_SAMPLE_MS,
        sample_nfc ? "; NFC presence" : "");
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    if(setup_ok && !cancelled) {
        diag_model_set_product_metadata(
            &instance->model,
            sample_nfc ? "Passive LF + NFC reader-field monitor" :
                         "Passive LF reader-field monitor",
            version);
    }
    diag_lf_apply_finish(&instance->model, &instance->stats, cancelled, deadline);
    furi_mutex_release(instance->mutex);
    if(setup_ok && !cancelled && deadline) {
        diag_lf_log(
            instance,
            DiagLogSuccess,
            DiagStageComplete,
            "Bounded passive reader-field observation complete; no brand or strength inferred");
    }
    diag_lf_finish_running(instance, setup_ok && !cancelled && deadline);
    return 0;
}

static int32_t diag_lf_worker(void* context) {
    DiagLf* instance = context;
    return instance->stats.mode == DiagLfModeCard ? diag_lf_card_worker(instance) :
                                                    diag_lf_reader_worker(instance);
}

DiagLf* diag_lf_alloc(void) {
    DiagLf* instance = calloc(1, sizeof(DiagLf));
    furi_check(instance);
    instance->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    instance->events = furi_event_flag_alloc();
    instance->thread = furi_thread_alloc_ex("NfcDiagLf", 3072, diag_lf_worker, instance);
    diag_model_init(&instance->model, DiagProvenanceLive);
    return instance;
}

void diag_lf_free(DiagLf* instance) {
    if(!instance) return;
    diag_lf_cancel(instance);
    if(instance->thread_started) furi_thread_join(instance->thread);
    furi_thread_free(instance->thread);
    furi_event_flag_free(instance->events);
    furi_mutex_free(instance->mutex);
    free(instance);
}

bool diag_lf_start(DiagLf* instance, DiagLfMode mode) {
    furi_check(instance);
    if(mode != DiagLfModeCard && mode != DiagLfModeReader &&
       mode != DiagLfModeReaderBoth) {
        return false;
    }
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    bool busy = instance->running;
    furi_mutex_release(instance->mutex);
    if(busy) return false;
    if(instance->thread_started) furi_thread_join(instance->thread);
    furi_event_flag_clear(instance->events, DIAG_LF_ALL_FLAGS);
    DateTime rtc;
    furi_hal_rtc_get_datetime(&rtc);
    char timestamp[DIAG_TIMESTAMP_CAPACITY];
    snprintf(
        timestamp,
        sizeof(timestamp),
        "%04u-%02u-%02uT%02u:%02u:%02u",
        rtc.year,
        rtc.month,
        rtc.day,
        rtc.hour,
        rtc.minute,
        rtc.second);
    char runtime[DIAG_RUNTIME_VERSION_CAPACITY];
    snprintf(
        runtime,
        sizeof(runtime),
        "%.14s %.12s",
        version_get_version(NULL),
        version_get_githash(NULL));
    instance->started_tick = furi_get_tick();
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    diag_model_init(&instance->model, DiagProvenanceLive);
    diag_model_set_timestamp(&instance->model, timestamp);
    diag_model_set_runtime_provenance(
        &instance->model, DIAG_FIRMWARE_BUILD, runtime);
    memset(&instance->stats, 0, sizeof(instance->stats));
    instance->stats.mode = mode;
    instance->stats.sample_period_ms =
        mode == DiagLfModeCard ? 0u : DIAG_LF_FIELD_SAMPLE_MS;
    instance->decoded_protocol = PROTOCOL_NO;
    instance->running = true;
    furi_mutex_release(instance->mutex);
    instance->thread_started = true;
    furi_thread_start(instance->thread);
    return true;
}

void diag_lf_cancel(DiagLf* instance) {
    if(instance) furi_event_flag_set(instance->events, DIAG_LF_FLAG_CANCEL);
}

bool diag_lf_is_running(DiagLf* instance) {
    furi_check(instance);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    bool running = instance->running;
    furi_mutex_release(instance->mutex);
    return running;
}

void diag_lf_snapshot(DiagLf* instance, DiagModel* model, DiagLfStats* stats) {
    furi_check(instance);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    if(model) *model = instance->model;
    if(stats) *stats = instance->stats;
    furi_mutex_release(instance->mutex);
}

bool diag_lf_read_model(
    DiagLf* instance, DiagModelReadCallback callback, void* context) {
    if(!instance || !callback) return false;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    callback(&instance->model, context);
    furi_mutex_release(instance->mutex);
    return true;
}

#endif
