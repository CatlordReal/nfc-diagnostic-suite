#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_port.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>
#include <dolphin/dolphin.h>
#include <toolbox/version.h>
#include <loader/loader.h>
#include <furi/core/memmgr_heap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "diag_build.h"
#include "diag_model.h"
#include "diag_nfc.h"
#include "diag_files.h"
#include "diag_ui.h"
#include "diag_lf.h"
#include "diag_reader.h"
#include "diag_workflow.h"
#include "diag_capabilities.h"

#define REPORT_DIR EXT_PATH("apps_data/nfc_diagnostic_suite")

typedef enum { RadioNone, RadioNfc, RadioLfCard, RadioLfReader, RadioReader } DiagRadio;
typedef enum { MenuHome, MenuReader, MenuWorkflowStart, MenuWorkflow, MenuSaved, MenuSessions, MenuWorkflowTools } DiagMenu;
#define ITEM_COUNT(items) (sizeof(items) / sizeof((items)[0]))

typedef struct {
    DiagUi ui;
    FuriMutex* ui_mutex;
    FuriMessageQueue* inputs;
    ViewPort* viewport;
    Gui* gui;
    Storage* storage;
    DialogsApp* dialogs;
    DiagNfc* nfc;
    DiagLf* lf;
    DiagReader* reader;
    DiagRadio radio;
    DiagRadio last_radio;
    DiagWorkflowBand last_card_band;
    DiagMenu menu;
    size_t menu_positions[7];
    DiagStep step;
    bool pending_file;
    bool file_from_workflow;
    bool showing_reference;
    DiagWorkflow workflow;
    DiagCapabilities source_caps;
    bool source_valid;
    bool reader_stats_valid;
    bool lf_reader_stats_valid;
    bool last_reader_band_report;
    bool reader_success;
    bool library_pairs_available;
    bool workflow_radio;
    bool current_for_workflow;
    bool workflow_save_failed;
    const char* workflow_labels[16];
    unsigned workflow_actions[16];
    size_t workflow_action_count;
    const char* reader_labels[6];
    unsigned reader_actions[6];
    DiagReaderStats reader_stats;
    DiagLfStats lf_stats;
    bool reader_from_workflow;
    bool auto_band;
    char fallback_detail[DIAG_LOG_MESSAGE_CAPACITY];
    bool cancelled;
    bool leave;
    uint32_t confirm_action;
    DiagModel* current;
    DiagObservation baseline;
    char baseline_timestamp[DIAG_TIMESTAMP_CAPACITY];
    bool has_current;
    bool has_baseline;
    bool active;
    bool show_live_log;
    bool log_follow;
    bool repeat;
    bool success_xp_given;
    bool save_xp_given;
    size_t completed_runs;
    size_t serial_log_count;
    size_t reference;
    DiagObservation* observations;
    FuriString* text;
    FuriString* message;
} DiagApp;

_Static_assert(sizeof(DiagApp) < 6144u, "App state exceeds startup RAM budget");

static void ui_show(DiagApp* app, const char* title, const char* text, bool preserve) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->ui.scanning = app->active;
    diag_ui_text(&app->ui, title, text, preserve);
    furi_mutex_release(app->ui_mutex);
    furi_string_reset(app->text);
}
static void draw(Canvas* canvas, void* context) {
    DiagApp* app = context;
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    diag_ui_draw(canvas, &app->ui);
    furi_mutex_release(app->ui_mutex);
}
static void input(InputEvent* event, void* context) {
    DiagApp* app = context;
    if(event->type == InputTypeShort ||
       (event->type == InputTypeRepeat && (event->key == InputKeyUp || event->key == InputKeyDown)))
        furi_message_queue_put(app->inputs, event, 0);
}
static bool ensure_current(DiagApp* app) {
    if(app->current) return true;
    if(memmgr_get_free_heap() < sizeof(DiagModel) + 2048u ||
       memmgr_heap_get_max_free_block() < sizeof(DiagModel) + 8u) {
        ui_show(app, "Low memory", "Session cannot fit.\nClose extra tools; retry.", false);
        return false;
    }
    app->current = calloc(1, sizeof(DiagModel));
    return app->current != NULL;
}
static void discard_current(DiagApp* app) {
    free(app->current);
    app->current = NULL;
    app->has_current = false;
    app->current_for_workflow = false;
}
static void discard_observations(DiagApp* app) {
    free(app->observations);
    app->observations = NULL;
}
static void timestamp(char* out, size_t size, bool filename) {
    DateTime now;
    furi_hal_rtc_get_datetime(&now);
    snprintf(out, size, filename ? "%04u%02u%02u-%02u%02u%02u" : "%04u-%02u-%02uT%02u:%02u:%02u",
             now.year, now.month, now.day, now.hour, now.minute, now.second);
}
static void uid_text(FuriString* text, const uint8_t* uid, size_t count) {
    for(size_t i = 0; i < count; i++)
        furi_string_cat_printf(text, "%s%02X", i ? " " : "", uid[i]);
    furi_string_cat_str(text, "\n");
}
static bool workflow_restore_source(DiagApp* app);
static void show_menu(DiagApp* app, DiagMenu menu);
static void workflow_page(DiagApp* app);
static bool visit_radio(DiagApp* app, DiagModelReadCallback callback, void* context);
static void reader_report(DiagApp* app);
static void lf_report(DiagApp* app);
static void results(DiagApp* app) {
    if(app->last_radio == RadioReader) { reader_report(app); return; }
    if(app->last_radio == RadioLfReader) { lf_report(app); return; }
    furi_string_reset(app->text);
    if(!app->has_current) {
        ui_show(app, "Card details", "No session.\nChoose Identify card.", false);
        return;
    }
    const DiagModel* model = app->current;
    furi_string_cat_printf(app->text, "%s\n%s\n%s\n", diag_provenance_name(model->provenance),
                           model->timestamp[0] ? model->timestamp : "Timestamp not recorded", model->run_succeeded ? "Inspection complete" : "Incomplete / failed");
    if(model->provenance == DiagProvenanceSaved)
        furi_string_cat_printf(app->text, "Recorded source: %s\n", diag_provenance_name(model->recorded_provenance));
    if(model->identity.present) {
        furi_string_cat_str(app->text, model->identity.protocol == DiagProtocolLfRfid ? "Decoded LF data:\n" : "UID (API byte order):\n");
        uid_text(app->text, model->identity.uid, model->identity.uid_size);
        if(model->identity.may_randomize)
            furi_string_cat_str(app->text, "Identifier may randomize.\nPhysical-card correlation\nacross probes unavailable.\n");
    }
    if(model->iso_a.present) {
        furi_string_cat_str(app->text, "ISO14443-A UID:\n");
        uid_text(app->text, model->iso_a.uid, model->iso_a.uid_size);
        furi_string_cat_printf(app->text,
            "ATQA: %02X %02X (MSB)\nSAK: %02X (final)\nCascade levels: %u\nDerived from UID size.\nIntermediate SAK/BCC\nnot exposed by API.\n",
            model->iso_a.atqa[1], model->iso_a.atqa[0], model->iso_a.sak, model->iso_a.cascade_count);
    }
    if(model->iso_a.present && ((model->protocol_candidates | model->protocols_confirmed) & (1u << DiagProtocolMfClassic))) {
        furi_string_cat_printf(app->text, "Classic family: %s\nCapacity hint: %s\nSAK only; size unverified.\n",
            model->protocols_confirmed & (1u << DiagProtocolMfClassic) ?
                model->provenance == DiagProvenanceSaved ? "recorded confirmation" : "command confirmed" : "candidate only",
            model->iso_a.sak == 0x08 ? "1K" : model->iso_a.sak == 0x18 ? "4K" : "unknown");
    }
    furi_string_cat_str(app->text, "\nProtocol evidence:\n");
    for(unsigned i = 0; i < DIAG_PROTOCOL_COUNT; i++) {
        if((model->protocol_candidates | model->protocols_confirmed) & (1u << i))
            furi_string_cat_printf(app->text, "%s\n  %s\n", diag_protocol_name(i),
                model->protocols_confirmed & (1u << i) ?
                    model->provenance == DiagProvenanceSaved ? "Recorded confirmation" : "Command confirmed" : "Candidate only");
    }
    furi_string_cat_printf(app->text, "\nProduct: %s\nVersion: %s\n", model->metadata.product,
                           model->metadata.version);
    furi_string_cat_str(app->text, "No authenticity proof.\nInspection is read-only.");
    ui_show(app, "Card details", furi_string_get_cstr(app->text), false);
}
static bool visit_radio(DiagApp* app, DiagModelReadCallback callback, void* context) {
    if(app->radio == RadioNfc) return diag_nfc_read_model(app->nfc, callback, context);
    if(app->radio == RadioReader) return diag_reader_read_model(app->reader, callback, context);
    if(app->radio == RadioLfCard || app->radio == RadioLfReader) return diag_lf_read_model(app->lf, callback, context);
    return false;
}
static void log_preview(const DiagModel* model, void* context) {
    DiagApp* app = context;
    if(furi_mutex_acquire(app->ui_mutex, 0) != FuriStatusOk) return;
    app->ui.scanning = app->active;
    diag_ui_logs(&app->ui, model, true, app->log_follow);
    furi_mutex_release(app->ui_mutex);
}
static void logs(DiagApp* app, bool preserve) {
    if(app->active) { visit_radio(app, log_preview, app); return; }
    if(!app->has_current || !app->current) { ui_show(app, "Event log", "No session recorded.", false); return; }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    diag_ui_logs(&app->ui, app->current, preserve, false);
    furi_mutex_release(app->ui_mutex);
}
typedef struct {
    DiagLogEntry entries[4];
    size_t count;
    size_t next;
} DiagLogBatch;
static void copy_log_batch(const DiagModel* model, void* context) {
    DiagLogBatch* batch = context;
    size_t first = batch->next > model->logs_dropped ? batch->next - model->logs_dropped : 0;
    if(first > model->log_count) first = model->log_count;
    batch->count = model->log_count - first;
    if(batch->count > ITEM_COUNT(batch->entries)) batch->count = ITEM_COUNT(batch->entries);
    for(size_t i = 0; i < batch->count; ++i) batch->entries[i] = model->logs[first + i];
    batch->next = model->logs_dropped + first + batch->count;
}
static size_t stream_logs(DiagApp* app) {
    DiagLogBatch batch = {.next = app->serial_log_count};
    if(!visit_radio(app, copy_log_batch, &batch)) return 0;
    app->serial_log_count = batch.next;
    for(size_t i = 0; i < batch.count; ++i)
        FURI_LOG_I("NfcDiag", "%lu ms %s", (unsigned long)batch.entries[i].elapsed_ms, batch.entries[i].message);
    return batch.count;
}
static void live_preview(const DiagModel* model, void* context) {
    DiagApp* app = context;
    if(furi_mutex_acquire(app->ui_mutex, 0) != FuriStatusOk) return;
    if(app->ui.log_view) diag_ui_logs(&app->ui, model, true, app->log_follow);
    else {
        char body[96];
        const char* band = app->radio == RadioNfc ? "NFC" : app->radio == RadioLfCard ? "125 kHz RFID" : "Reader";
        snprintf(body, sizeof(body), "%s\n%.28s", band, diag_stage_name(model->last_successful_stage));
        diag_ui_step(&app->ui, app->cancelled ? "Stopping" : "Reading", body, DiagUiArtScanning, "File", "", "Log");
    }
    app->ui.scanning = true;
    app->ui.animation_frame++;
    app->ui.run_number = app->repeat ? app->completed_runs + 1 : 0;
    furi_mutex_release(app->ui_mutex);
}
static void diagnose(DiagApp* app) {
    if(!app->has_current) {
        ui_show(app, "Diagnose", "No session.\nChoose Identify card.", false);
        return;
    }
    furi_string_printf(app->text, "Last successful stage:\n%s\n", diag_stage_name(app->current->last_successful_stage));
    if(app->current->error.present) furi_string_cat_printf(app->text, "Error: %s\nCode: %ld\n",
        app->current->error.domain, (long)app->current->error.code);
    furi_string_cat_printf(app->text, "\n%s\n\nLikely causes only;\nnot measurements.\nNo RSSI, range,\nantenna tuning or\nRF waveform API.",
                           diag_stage_advice(app->current->last_successful_stage));
    ui_show(app, "Diagnose", furi_string_get_cstr(app->text), false);
}
static void reference(DiagApp* app) {
    const DiagProtocolReference* entry = diag_protocol_reference(app->reference);
    furi_string_printf(app->text, "%s\n%s\n%s\n\n%s\n\nLeft/Right: protocol",
        entry->name, entry->family, entry->standard, entry->diagnostic_note);
    app->showing_reference = true;
    ui_show(app, "Protocol reference", furi_string_get_cstr(app->text), false);
}
static void save(DiagApp* app) {
    if(!app->has_current) {
        ui_show(app, "Save", "No session to save.", false);
        return;
    }
    char stamp[32];
    DiagFilesExportResult exported;
    timestamp(stamp, sizeof(stamp), true);
    DiagFileStatus status = diag_files_export_reports(app->storage, REPORT_DIR, stamp, app->current,
        &exported, app->message);
    if(status != DiagFileStatusOk) {
        ui_show(app, "Export failed", furi_string_get_cstr(app->message), false);
        return;
    }
    status = diag_files_save_session(app->storage, exported.session_path, app->current, app->message);
    if(status == DiagFileStatusOk && app->current->provenance == DiagProvenanceLive &&
       app->current->run_succeeded && app->current->identity.present &&
       (app->last_radio == RadioNfc || app->last_radio == RadioLfCard) && !app->save_xp_given) {
        dolphin_deed(app->current->identity.protocol == DiagProtocolLfRfid ? DolphinDeedRfidSave : DolphinDeedNfcSave);
        app->save_xp_given = true;
    }
    if(status != DiagFileStatusOk) {
        furi_string_printf(app->text, "JSON: %s\nCSV: %s\nSession failed: %s", exported.json_path, exported.csv_path, furi_string_get_cstr(app->message));
        ui_show(app, "Partial save", furi_string_get_cstr(app->text), false);
    } else { app->step = StepSaved; workflow_page(app); }

}
static void browse(DiagApp* app, unsigned kind) {
    bool nfc_file = kind == 1, lf_file = kind == 2;
    FuriString* path = furi_string_alloc_set(nfc_file ? EXT_PATH("nfc") : lf_file ? EXT_PATH("lfrfid") : REPORT_DIR);
    DialogsFileBrowserOptions options;
    dialog_file_browser_set_basic_options(&options, nfc_file ? ".nfc" : lf_file ? ".rfid" : ".nds", NULL);
    options.base_path = nfc_file ? EXT_PATH("nfc") : lf_file ? EXT_PATH("lfrfid") : REPORT_DIR;
    view_port_enabled_set(app->viewport, false);
    bool chosen = dialog_file_browser_show(app->dialogs, path, path, &options);
    view_port_enabled_set(app->viewport, true);
    if(chosen && ensure_current(app)) {
        DiagFileStatus status = nfc_file ?
            diag_files_validate_nfc(app->storage, furi_string_get_cstr(path), app->current, app->message) : lf_file ?
            diag_files_validate_rfid(app->storage, furi_string_get_cstr(path), app->current, app->message) :
            diag_files_load_session(app->storage, furi_string_get_cstr(path), app->current, app->message);
        if(status == DiagFileStatusOk) {
            app->has_current = true;
            app->last_radio = RadioNone;
            app->current_for_workflow = false;
            app->save_xp_given = true;
            results(app);
        } else {
            ui_show(app, "File check", furi_string_get_cstr(app->message), false);
        }
    }
    furi_string_free(path);
}
static void compare(DiagApp* app) {
    if(!app->has_baseline || !app->has_current) {
        ui_show(app, "Compare", "Load or scan a card.\nSet baseline, then\nload/scan another.\nChoose Compare.", false);
        return;
    }
    DiagObservation observed;
    if(!diag_model_observe(app->current, &observed)) return;
    DiagComparison result = diag_observation_compare(&app->baseline, &observed);
    furi_string_printf(app->text, "Baseline: %s\nCurrent: %s\nIdentity: %s\nProtocols: %s\nMetadata: %s\nOutcome: %s\n\nCompares diagnostic\nidentity and metadata;\nnot card contents.\nMissing data is not\nproof of equality.",
        app->baseline_timestamp, app->current->timestamp,
        result.identity_same ? "same" : "different / absent",
        result.protocols_same ? "same" : "different",
        result.metadata_same ? "same" : "different / absent",
        result.outcome_same ? "same" : "different");
    char evidence[96];
    snprintf(evidence, sizeof(evidence), "Comparison: identity=%s protocol=%s metadata=%s outcome=%s",
        result.identity_same ? "same" : "diff", result.protocols_same ? "same" : "diff",
        result.metadata_same ? "same" : "diff", result.outcome_same ? "same" : "diff");
    diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, evidence);
    ui_show(app, "Comparison", furi_string_get_cstr(app->text), false);
}
static void repeat_results(DiagApp* app) {
    DiagRepeatability result;
    if(!diag_observations_analyze(app->observations, &result)) {
        ui_show(app, "Repeat test", "Invalid observations.", false);
        return;
    }
    furi_string_printf(app->text, "%u runs\nSuccess: %u  Fail: %u\nIdentity: %s\nProtocols: %s\nMetadata: %s\nOutcome: %s\n\nFailures included.\nKeep one card still.\nUID randomization or\ncard movement can\nchange results.\nSave exports last run\nwith repeat summary.",
        (unsigned)result.run_count, (unsigned)result.successful_runs, (unsigned)result.failed_runs,
        result.identity_repeatable ? "stable" : "unstable / absent",
        result.protocols_repeatable ? "stable" : "unstable / absent",
        result.metadata_repeatable ? "stable" : "unstable / absent",
        result.outcome_repeatable ? "stable" : "unstable");
    uint32_t elapsed = app->current->log_count ? app->current->logs[app->current->log_count - 1].elapsed_ms : 0;
    for(size_t i = 0; i < DIAG_REPEATABILITY_RUNS; i++) {
        const DiagObservation* observation = &app->observations[i];
        char detail[DIAG_LOG_MESSAGE_CAPACITY];
        snprintf(detail, sizeof(detail), "Run %u: %s; stage=%s; candidate=%04lX confirmed=%04lX",
            (unsigned)i + 1, observation->run_succeeded ? "pass" : "fail",
            diag_stage_name(observation->last_successful_stage),
            (unsigned long)observation->protocol_candidates, (unsigned long)observation->protocols_confirmed);
        diag_model_add_log_at(app->current, DiagLogInfo, app->current->last_successful_stage, elapsed, detail);
        size_t used = (size_t)snprintf(detail, sizeof(detail), "Run %u UID=", (unsigned)i + 1);
        if(observation->identity.present) {
            for(size_t j = 0; j < observation->identity.uid_size && used + 3 < sizeof(detail); j++)
                used += (size_t)snprintf(detail + used, sizeof(detail) - used, "%02X", observation->identity.uid[j]);
        } else snprintf(detail + used, sizeof(detail) - used, "unavailable");
        diag_model_add_log_at(app->current, DiagLogInfo, app->current->last_successful_stage, elapsed, detail);
        if(observation->metadata.product[0]) {
            snprintf(detail, sizeof(detail), "Run %u product=%s", (unsigned)i + 1, observation->metadata.product);
            diag_model_add_log_at(app->current, DiagLogInfo, app->current->last_successful_stage, elapsed, detail);
        }
        if(observation->metadata.version[0]) {
            snprintf(detail, sizeof(detail), "Run %u version=%s", (unsigned)i + 1, observation->metadata.version);
            diag_model_add_log_at(app->current, DiagLogInfo, app->current->last_successful_stage, elapsed, detail);
        }
        if(observation->error.present) {
            snprintf(detail, sizeof(detail), "Run %u error=%s code=%ld", (unsigned)i + 1,
                observation->error.domain, (long)observation->error.code);
            diag_model_add_log_at(app->current, DiagLogWarning, app->current->last_successful_stage, elapsed, detail);
        }
    }
    char summary[96];
    snprintf(summary, sizeof(summary), "Repeat: %u/5 passed; UID=%s protocol=%s metadata=%s",
        (unsigned)result.successful_runs, result.identity_repeatable ? "stable" : "varies",
        result.protocols_repeatable ? "stable" : "varies", result.metadata_repeatable ? "stable" : "varies");
    diag_model_add_log_at(app->current, DiagLogInfo, app->current->last_successful_stage, elapsed, summary);
    ui_show(app, "Repeat test", furi_string_get_cstr(app->text), false);
}
static void release_radio(DiagApp* app) {
    diag_nfc_free(app->nfc); app->nfc = NULL;
    diag_lf_free(app->lf); app->lf = NULL;
    diag_reader_free(app->reader); app->reader = NULL;
    app->radio = RadioNone;
}
static bool workflow_context(DiagApp* app) {
    return app->menu == MenuWorkflow || app->menu == MenuWorkflowTools || (app->menu == MenuReader && app->reader_from_workflow);
}
static bool persist_workflow(DiagApp* app, bool show_error) {
    bool saved = diag_workflow_save(app->storage, &app->workflow, app->message) == DiagFileStatusOk;
    app->workflow_save_failed = !saved;
    if(!saved) {
        if(app->has_current) diag_model_add_log(app->current, DiagLogError, app->current->last_successful_stage,
            "Workflow save failed; radio evidence retained; disk progress may be older");
        if(show_error) ui_show(app, "Workflow save failed", furi_string_get_cstr(app->message), false);
    }
    return saved;
}
static bool radio_memory(DiagApp* app, bool card_reader, bool repeat, bool reclaim) {
    /* Reserve includes one engine/model, stacks, native data and RX buffers. */
    size_t needed = (card_reader ? 40u * 1024u : 24u * 1024u) + (repeat ? DIAG_REPEATABILITY_RUNS * sizeof(DiagObservation) : 0);
    size_t available = memmgr_get_free_heap() + (reclaim && app->current ? sizeof(DiagModel) : 0) +
        (reclaim && app->observations ? DIAG_REPEATABILITY_RUNS * sizeof(DiagObservation) : 0);
    if(available >= needed && memmgr_heap_get_max_free_block() >= 12u * 1024u) return true;
    furi_string_printf(app->text, "Free RAM: %u bytes\nNeed reserve: %u\nLargest block: %u\nClose other tools or\nrestart Flipper; retry.\nRadio not started.",
        (unsigned)memmgr_get_free_heap(), (unsigned)needed, (unsigned)memmgr_heap_get_max_free_block());
    ui_show(app, "Low memory", furi_string_get_cstr(app->text), false);
    return false;
}
static bool allocate_observations(DiagApp* app, bool repeat) {
    if(!repeat) return true;
    app->observations = calloc(DIAG_REPEATABILITY_RUNS, sizeof(DiagObservation));
    if(app->observations) return true;
    app->repeat = false;
    ui_show(app, "Repeat unavailable", "Insufficient RAM.\nRadio not started.", false);
    return false;
}
static void start(DiagApp* app, bool repeat) {
    release_radio(app);
    app->active = false;
    if(!radio_memory(app, true, repeat, true)) return;
    release_radio(app);
    app->active = false;
    discard_current(app);
    discard_observations(app);
    furi_string_reset(app->text);
    app->workflow_radio = workflow_context(app);
    app->current_for_workflow = false;
    app->repeat = repeat;
    if(!radio_memory(app, true, repeat, false) || !allocate_observations(app, repeat)) return;
    app->nfc = diag_nfc_alloc();
    app->radio = RadioNfc;
    app->auto_band = false;
    app->fallback_detail[0] = 0;
    app->cancelled = false;
    app->repeat = repeat;
    app->completed_runs = 0;
    app->success_xp_given = false;
    app->save_xp_given = false;
    app->serial_log_count = 0;
    app->show_live_log = false;
    app->log_follow = true;
    app->active = diag_nfc_start(app->nfc);
    app->has_current = false;
    if(app->active) {
        dolphin_deed(DolphinDeedNfcRead);
        visit_radio(app, live_preview, app);
    } else ui_show(app, "Busy", "NFC worker draining.\nTry after it stops.", false);
}
static DiagCapabilities workflow_capabilities(DiagApp* app) {
    if(app->source_valid) return app->source_caps;
    if(!app->current_for_workflow) return diag_capabilities_for(NULL);
    DiagCapabilities caps = diag_capabilities_for(app->has_current ? app->current : NULL);
    if((app->workflow.band == DiagWorkflowBandNfc && caps.is_nfc) ||
       (app->workflow.band == DiagWorkflowBandLf && caps.is_lf)) return caps;
    return diag_capabilities_for(NULL);
}
static void workflow_page(DiagApp* app) {
    app->menu = MenuWorkflow;
    app->confirm_action = 0;
    app->showing_reference = false;
    const char* title = app->workflow.have_card ? "Read card" : "Test reader";
    char body[192] = {0};
    const char* center = "Read";
    const char* right = "Tools";
    DiagUiArt art = app->workflow.have_card ? DiagUiArtCard : DiagUiArtReader;
    if(app->step == StepCardReady) snprintf(body, sizeof(body), "Hold card nearby.\nNFC / LF auto");
    else if(app->step == StepReaderReady) {
        snprintf(body, sizeof(body), "Hold near reader.\nNFC / LF fields"); center = "Scan";
    } else if(app->step == StepChooseFile) {
        snprintf(body, sizeof(body), "Select saved card\nto continue."); center = "File";
    } else if(app->step == StepVerifyCopy) {
        title = "Check saved copy";
        snprintf(body, sizeof(body), "Read blank to a\nNEW file, then\ncompare here."); center = "Compare";
    } else if(app->step == StepReread) {
        title = "Re-read original";
        snprintf(body, sizeof(body), "Read original\nwith recovered\nkeys; save file."); center = "Read";
    } else if(app->step == StepSaved) {
        title = "Report saved"; center = "Done"; art = DiagUiArtSuccess;
        snprintf(body, sizeof(body), "Report files\nsaved on SD");
    } else if(app->last_radio == RadioLfReader) {
        title = "Reader fields"; center = "Save"; right = "Tests"; art = DiagUiArtNone;
        snprintf(body, sizeof(body), "NFC: %s  LF: %s\nField observation\n%s", app->lf_stats.nfc_field_seen ? "yes" : "no",
            app->lf_stats.field_seen ? "yes" : "no", app->current && app->current->error.present ? "Error; see Tests" : "Type not identified");
    } else if(app->last_radio == RadioReader) {
        title = "Reader observation"; art = DiagUiArtNone;
        snprintf(body, sizeof(body), "Selected: %lu\nRequests: %lu\nPairs saved: %lu", (unsigned long)app->reader_stats.selection_count,
            (unsigned long)app->reader_stats.request_count, (unsigned long)app->reader_stats.pairs_saved);
        center = "Save";
    } else if(app->has_current && app->current) {
        title = app->current->run_succeeded ? "Card inspected" : "Read incomplete";
        art = DiagUiArtNone;
        center = "Save";
        const char* type = app->current->metadata.product[0] ? app->current->metadata.product :
            app->current->identity.present ? diag_protocol_name(app->current->identity.protocol) : "No card identified";
        if(app->current->protocols_confirmed & (1u << DiagProtocolMfClassic))
            type = app->current->iso_a.sak == 0x08 ? "Classic 1K (size hint)" :
                app->current->iso_a.sak == 0x18 ? "Classic 4K (size hint)" : "Classic-compatible";
        const char* evidence = app->current->provenance == DiagProvenanceSaved ? "Saved evidence" :
            app->current->protocols_confirmed ? "Command confirmed" : "Candidate / incomplete";
        if(app->current->identity.present) {
            char id[25] = {0};
            size_t count = app->current->identity.uid_size < 8 ? app->current->identity.uid_size : 8;
            for(size_t i = 0; i < count; ++i) snprintf(id + 2*i, sizeof(id) - 2*i, "%02X", app->current->identity.uid[i]);
            snprintf(body, sizeof(body), "%.21s\n%s\n%s%s", type, evidence, id, app->current->identity.uid_size > count ? "..." : "");
        } else snprintf(body, sizeof(body), "%.21s\n%.21s\nTools: details", type,
            app->current->error.present ? app->current->error.domain : "Try repositioning");
    }
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    diag_ui_step(&app->ui, title, body, art, "File", center, right);
    furi_mutex_release(app->ui_mutex);
}
static bool native_tool_available(DiagApp* app, const char* path) {
    FileInfo info;
    return storage_common_stat(app->storage, path, &info) == FSE_OK && !(info.flags & FSF_DIRECTORY);
}
static void show_menu(DiagApp* app, DiagMenu menu) {
    app->menu_positions[app->menu] = app->ui.selected;
    app->menu = menu;
    app->confirm_action = 0;
    app->showing_reference = false;
    if(menu == MenuWorkflow) { workflow_page(app); return; }
    bool mfkey_available = menu == MenuWorkflowTools && native_tool_available(app, EXT_PATH("apps/NFC/mfkey.fap"));
    bool picopass_available = menu == MenuWorkflowTools && native_tool_available(app, EXT_PATH("apps/NFC/picopass.fap"));
    bool magic_available = menu == MenuWorkflowTools && native_tool_available(app, EXT_PATH("apps/NFC/nfc_magic.fap"));
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    if(menu == MenuReader) {
        unsigned band = app->reader_from_workflow ? app->workflow.band : DiagWorkflowBandUnknown;
        size_t count = 0;
        DiagCapabilities caps = workflow_capabilities(app);
        for(unsigned i = 0; i < ITEM_COUNT(diag_reader_menu_items); ++i) {
            if(band == DiagWorkflowBandLf && i >= 1 && i <= 3) continue;
            if(band == DiagWorkflowBandNfc && i == 4) continue;
            if(app->reader_from_workflow && caps.has_identity) {
                if(i == 3 && !caps.classic) continue;
                if(i == 2 && !app->workflow.identity.present) continue;
            }
            app->reader_actions[count] = i;
            app->reader_labels[count++] = diag_reader_menu_items[i];
        }
        diag_ui_menu(&app->ui, "Reader tests", app->reader_labels, count);
    } else if(menu == MenuWorkflowStart) diag_ui_menu(&app->ui, "What do you have?", diag_workflow_start_items, 2);
    else if(menu == MenuSaved) diag_ui_menu(&app->ui, "Saved cards", diag_saved_menu_items, 2);
    else if(menu == MenuSessions) diag_ui_menu(&app->ui, "Sessions", diag_session_menu_items, 6);
    else if(menu == MenuWorkflowTools) {
        unsigned all[16];
        size_t count = diag_capabilities_workflow_actions(workflow_capabilities(app), app->workflow.band,
            app->workflow.have_card, app->source_valid, app->library_pairs_available, all, ITEM_COUNT(all));
        app->workflow_action_count = 0;
        for(size_t i = 0; i < count; ++i) {
            /* File and Save are already buttons on the workflow page. */
            if(all[i] == 5 || all[i] == 6 || all[i] == 12) continue;
            if(all[i] == 8 && !mfkey_available) continue;
            if(all[i] == 14 && !picopass_available) continue;
            if(all[i] == 9) {
                DiagCapabilities caps = workflow_capabilities(app);
                if(!caps.can_native_write && !magic_available) continue;
            }
            size_t out = app->workflow_action_count++;
            app->workflow_actions[out] = all[i];
            app->workflow_labels[out] = diag_workflow_menu_items[all[i]];
        }
        diag_ui_menu(&app->ui, "Card actions", app->workflow_labels, app->workflow_action_count);
    } else diag_ui_menu(&app->ui, "NFC Diagnostic Suite", diag_menu_items, DIAG_MENU_COUNT);
    size_t selected = app->menu_positions[menu];
    app->ui.selected = selected < app->ui.menu_count ? selected : app->ui.menu_count - 1;
    furi_mutex_release(app->ui_mutex);
}
static void snapshot_radio(DiagApp* app) {
    if(app->radio == RadioNfc) diag_nfc_snapshot(app->nfc, app->current);
    else if(app->radio == RadioReader) diag_reader_snapshot(app->reader, app->current, &app->reader_stats);
    else if(app->radio == RadioLfCard || app->radio == RadioLfReader)
        diag_lf_snapshot(app->lf, app->current, &app->lf_stats);
}
static bool radio_running(DiagApp* app) {
    if(app->radio == RadioNfc) return diag_nfc_is_running(app->nfc);
    if(app->radio == RadioReader) return diag_reader_is_running(app->reader);
    if(app->radio == RadioLfCard || app->radio == RadioLfReader) return diag_lf_is_running(app->lf);
    return false;
}
static void cancel_radio(DiagApp* app) {
    if(app->radio == RadioNfc) diag_nfc_cancel(app->nfc);
    else if(app->radio == RadioReader) diag_reader_cancel(app->reader);
    else if(app->radio == RadioLfCard || app->radio == RadioLfReader) diag_lf_cancel(app->lf);
}
static void prepare_run(DiagApp* app) {
    release_radio(app);
    app->active = false;
    discard_current(app);
    discard_observations(app);
    furi_string_reset(app->text);
    app->workflow_radio = workflow_context(app);
    app->current_for_workflow = false;
    app->repeat = false;
    app->auto_band = false;
    app->fallback_detail[0] = 0;
    app->cancelled = false;
    app->success_xp_given = false;
    app->save_xp_given = false;
    app->serial_log_count = 0;
    app->show_live_log = false;
    app->log_follow = true;
}
static void start_lf(DiagApp* app, DiagLfMode mode, bool repeat) {
    release_radio(app);
    app->active = false;
    if(!radio_memory(app, mode == DiagLfModeCard, repeat, true)) return;
    prepare_run(app);
    app->repeat = repeat;
    if(!radio_memory(app, mode == DiagLfModeCard, repeat, false) || !allocate_observations(app, repeat)) return;
    app->completed_runs = 0;
    app->lf = diag_lf_alloc();
    app->radio = mode == DiagLfModeCard ? RadioLfCard : RadioLfReader;
    app->active = diag_lf_start(app->lf, mode);
    app->has_current = false;
    if(app->active) {
        if(mode == DiagLfModeCard) dolphin_deed(DolphinDeedRfidRead);
        visit_radio(app, live_preview, app);
    } else ui_show(app, "Start failed", "LF worker unavailable.\nRadio not started.", false);
}
static void start_reader(DiagApp* app, DiagReaderMode mode) {
    release_radio(app);
    app->active = false;
    if(!radio_memory(app, mode == DiagReaderModeClassic, false, true)) return;
    DiagIsoAIdentity identity = {0};
    if(workflow_context(app)) {
        if(app->workflow.identity.present) identity = app->workflow.identity;
    } else if(app->has_current) identity = app->current->iso_a;
    prepare_run(app);
    if(!radio_memory(app, mode == DiagReaderModeClassic, false, false)) return;
    app->reader = diag_reader_alloc();
    app->radio = RadioReader;
    app->active = diag_reader_start(app->reader, mode, identity.present ? &identity : NULL);
    app->has_current = false;
    if(app->active) visit_radio(app, live_preview, app);
    else ui_show(app, "Start failed", "Reader worker busy or\nidentity unsupported.\nNo test started.", false);
}
static void reader_report(DiagApp* app) {
    if(!app->reader_stats_valid) { ui_show(app, "Reader report", "No reader probe yet.", false); return; }
    const DiagReaderStats* s = &app->reader_stats;
    furi_string_printf(app->text, "%s\n%s\nElapsed: %lu ms\n", diag_reader_mode_name(s->mode),
        s->inconclusive ? "Inconclusive" : app->reader_success ? "Observation complete" : "Stopped / incomplete", (unsigned long)s->elapsed_ms);
    if(s->field_available) furi_string_cat_printf(app->text,
        "Field seen: %s\nSamples: %lu\nPeriod: %lu ms\nOn/off edges: %lu/%lu\nOn/off time: %lu/%lu ms\nSampled durations.\n",
        s->field_observed ? "yes" : "no", (unsigned long)s->samples, (unsigned long)s->sample_period_ms,
        (unsigned long)s->field_on_count, (unsigned long)s->field_off_count,
        (unsigned long)s->field_on_ms, (unsigned long)s->field_off_ms);
    else furi_string_cat_str(app->text, "Field totals unavailable\nin Classic listener.\n");
    if(s->selection_available) furi_string_cat_printf(app->text, "Selections: %lu\n", (unsigned long)s->selection_count);
    else furi_string_cat_str(app->text, "Selection count unavailable.\n");
    if(s->rx_total_available) furi_string_cat_printf(app->text, "RX frames: %lu\nRequests: %lu\nRequest gap: %lu..%lu ms\nNot RF latency.\n",
        (unsigned long)s->rx_count, (unsigned long)s->request_count,
        (unsigned long)s->min_request_gap_ms, (unsigned long)s->max_request_gap_ms);
    if(s->mode == DiagReaderModeClassic) furi_string_cat_printf(app->text,
        "Transcripts: %lu\nDuplicates: %lu\nRejected: %lu\nPairs: %lu\nSaved: %lu\nAlready saved: %lu\nLibrary: nfc/.mfkey32.log\nDecode: Card workflow\nthen MFKey.\n",
        (unsigned long)s->transcripts_collected, (unsigned long)s->transcript_duplicates,
        (unsigned long)s->transcript_rejected, (unsigned long)s->nonce_pairs,
        (unsigned long)s->pairs_saved, (unsigned long)s->pairs_already_saved);
    furi_string_cat_printf(app->text, "Errors: %lu\nLost events: %lu\nStorage error: %ld\n\nNo brand identification.\nNo response may mean\nwrong protocol/UID,\nprotected reader, or\npoor coupling.\nSave + export retains\ncounters in event log.",
        (unsigned long)s->error_count, (unsigned long)s->events_dropped, (long)s->storage_error);
    ui_show(app, "Reader report", furi_string_get_cstr(app->text), false);
}
static void lf_report(DiagApp* app) {
    if(!app->lf_reader_stats_valid) { ui_show(app, "Reader bands", "No field observation yet.", false); return; }
    const DiagLfStats* s = &app->lf_stats;
    furi_string_printf(app->text,
        "Passive reader fields\nElapsed: %lu ms\nPeriod: %lu ms\nSamples: %lu\nLF field seen: %s\nLF present/absent:\n%lu / %lu samples\nCounter: %lu Hz\nMin/max: %lu/%lu Hz\n",
        (unsigned long)s->elapsed_ms, (unsigned long)s->sample_period_ms, (unsigned long)s->samples_total,
        s->field_seen ? "yes" : "no", (unsigned long)s->field_present_samples, (unsigned long)s->field_absent_samples,
        (unsigned long)s->frequency_hz_last, (unsigned long)s->frequency_hz_min, (unsigned long)s->frequency_hz_max);
    if(s->mode == DiagLfModeReaderBoth) furi_string_cat_printf(app->text,
        "NFC field seen: %s\nNFC present/absent:\n%lu / %lu samples\n",
        s->nfc_field_seen ? "yes" : "no", (unsigned long)s->nfc_field_present_samples, (unsigned long)s->nfc_field_absent_samples);
    furi_string_cat_str(app->text,
        "Field frequency is LF\ncounter output; not\ncalibrated metrology.\nNo protocol or brand\nconfirmed by field.\nNo field: reader may\nbe pulsed/asleep or\nout of coupling range.");
    ui_show(app, "Reader bands", furi_string_get_cstr(app->text), false);
}
static void append_reader_summary(DiagApp* app) {
    char line[DIAG_LOG_MESSAGE_CAPACITY];
    if(app->last_radio == RadioReader) {
        const DiagReaderStats* s = &app->reader_stats;
        snprintf(line, sizeof(line), "Reader stats: mode=%u errors=%lu lost=%lu elapsed=%lu ms", s->mode,
            (unsigned long)s->error_count, (unsigned long)s->events_dropped, (unsigned long)s->elapsed_ms);
        diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
        if(s->field_available) {
            snprintf(line, sizeof(line), "Field: period=%lu ms samples=%lu on/off edges=%lu/%lu",
                (unsigned long)s->sample_period_ms, (unsigned long)s->samples,
                (unsigned long)s->field_on_count, (unsigned long)s->field_off_count);
            diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
            snprintf(line, sizeof(line), "Sampled on/off durations=%lu/%lu ms", (unsigned long)s->field_on_ms, (unsigned long)s->field_off_ms);
            diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
        }
        if(s->selection_available || s->rx_total_available) {
            snprintf(line, sizeof(line), "Type A: selections=%lu RX=%lu requests=%lu gap=%lu..%lu ms",
                (unsigned long)s->selection_count, (unsigned long)s->rx_count, (unsigned long)s->request_count,
                (unsigned long)s->min_request_gap_ms, (unsigned long)s->max_request_gap_ms);
            diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
        }
        snprintf(line, sizeof(line), "Classic: transcripts=%lu duplicates=%lu rejected=%lu pairs=%lu",
            (unsigned long)s->transcripts_collected, (unsigned long)s->transcript_duplicates,
            (unsigned long)s->transcript_rejected, (unsigned long)s->nonce_pairs);
        diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
        snprintf(line, sizeof(line), "Nonce sync: saved=%lu existing=%lu storage=%ld",
            (unsigned long)s->pairs_saved, (unsigned long)s->pairs_already_saved, (long)s->storage_error);
        diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
    } else if(app->last_radio == RadioLfReader) {
        const DiagLfStats* s = &app->lf_stats;
        snprintf(line, sizeof(line), "Reader fields: period=%lu ms samples=%lu LF on/off=%lu/%lu",
            (unsigned long)s->sample_period_ms, (unsigned long)s->samples_total,
            (unsigned long)s->field_present_samples, (unsigned long)s->field_absent_samples);
        diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
        snprintf(line, sizeof(line), "LF counter Hz: last=%lu min=%lu max=%lu; no calibrated accuracy",
            (unsigned long)s->frequency_hz_last, (unsigned long)s->frequency_hz_min, (unsigned long)s->frequency_hz_max);
        diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
        if(s->mode == DiagLfModeReaderBoth) {
            snprintf(line, sizeof(line), "NFC field samples on/off=%lu/%lu; presence only, no protocol inference",
                (unsigned long)s->nfc_field_present_samples, (unsigned long)s->nfc_field_absent_samples);
            diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, line);
        }
    }
}
static void refresh_library(DiagApp* app) {
    DiagNonceLibraryInfo info;
    app->library_pairs_available = diag_reader_library_info(app->storage, &info, app->message) && info.valid_pair_lines;
}
static void nonce_library(DiagApp* app) {
    DiagNonceLibraryInfo info;
    bool ok = diag_reader_library_info(app->storage, &info, app->message);
    app->library_pairs_available = ok && info.valid_pair_lines;
    furi_string_printf(app->text,
        "Momentum shared library\nSD/nfc/.mfkey32.log\nExists: %s\nBytes: %llu\nValid pair lines: %lu\nMalformed: %lu\nOversized: %lu\nScan: %s\nUser dictionary: %lu\nSystem dictionary: %lu\nDictionary scan: %s\n\n%s\nNo keys shown/deleted.\nMFKey runs on Flipper.\nRecovered keys go to\nnfc/assets/\nmf_classic_dict_user.nfc\nMIFARE Classic only.",
        info.exists ? "yes" : "no", (unsigned long long)info.size_bytes, (unsigned long)info.valid_pair_lines,
        (unsigned long)info.malformed_lines, (unsigned long)info.oversized_lines,
        info.truncated ? "partial (1 MiB cap)" : "complete",
        (unsigned long)info.user_dictionary_entries, (unsigned long)info.system_dictionary_entries,
        info.user_dictionary_complete && info.system_dictionary_complete ? "complete" : "partial / absent",
        ok ? "Library read-only." : furi_string_get_cstr(app->message));
    ui_show(app, "Nonce library", furi_string_get_cstr(app->text), false);
}
static void workflow_guide(DiagApp* app, uint32_t returned) {
    app->step = diag_workflow_resume_step(&app->workflow, returned);
    workflow_page(app);
}
static bool choose_path(DiagApp* app, bool lf, FuriString* path) {
    const char* base = lf ? EXT_PATH("lfrfid") : EXT_PATH("nfc");
    furi_string_set(path, base);
    DialogsFileBrowserOptions options;
    dialog_file_browser_set_basic_options(&options, lf ? ".rfid" : ".nfc", NULL);
    options.base_path = base;
    view_port_enabled_set(app->viewport, false);
    bool chosen = dialog_file_browser_show(app->dialogs, path, path, &options);
    view_port_enabled_set(app->viewport, true);
    return chosen;
}
static void workflow_source(DiagApp* app, bool lf) {
    app->current_for_workflow = false;
    FuriString* path = furi_string_alloc();
    if(choose_path(app, lf, path) && ensure_current(app)) {
        DiagFileStatus status = lf ? diag_files_validate_rfid(app->storage, furi_string_get_cstr(path), app->current, app->message) :
            diag_files_validate_nfc(app->storage, furi_string_get_cstr(path), app->current, app->message);
        if(status == DiagFileStatusOk) {
            app->has_current = true; app->last_radio = RadioNone; app->save_xp_given = true;
            DiagWorkflow candidate = app->workflow;
            candidate.band = lf ? DiagWorkflowBandLf : DiagWorkflowBandNfc;
            candidate.identity = app->current->iso_a;
            snprintf(candidate.source_path, sizeof(candidate.source_path), "%s", furi_string_get_cstr(path));
            status = diag_workflow_save(app->storage, &candidate, app->message);
            app->workflow_save_failed = status != DiagFileStatusOk;
            if(status == DiagFileStatusOk) {
                app->workflow = candidate;
                app->source_caps = diag_capabilities_for(app->current);
                app->source_valid = true;
                app->current_for_workflow = true;
                app->step = app->workflow.have_card ? StepOutcome : StepReaderReady;
                workflow_page(app);
            } else {
                FuriString* failure = furi_string_alloc_set(app->message);
                app->has_current = false;
                app->source_valid = false;
                app->current_for_workflow = false;
                workflow_restore_source(app);
                furi_string_set(app->message, failure);
                furi_string_cat_str(app->message, "\nPrevious workflow retained.");
                furi_string_free(failure);
            }
        }
        if(status != DiagFileStatusOk) ui_show(app, "Source failed", furi_string_get_cstr(app->message), false);
    }
    furi_string_free(path);
}
static const char* completeness(DiagSavedReadCompleteness value) {
    return value == DiagSavedReadCompletenessComplete ? "complete" :
        value == DiagSavedReadCompletenessIncomplete ? "incomplete" : "not established";
}
static void workflow_verify(DiagApp* app) {
    if(!app->workflow.source_path[0]) {
        ui_show(app, "Verify", "Choose original source\nfile first. Read blank\ninto a DIFFERENT file;\nnever overwrite source.", false); return;
    }
    FuriString* copy = furi_string_alloc();
    bool lf = app->workflow.band == DiagWorkflowBandLf;
    if(choose_path(app, lf, copy)) {
        if(storage_common_equivalent_path(app->storage, app->workflow.source_path, furi_string_get_cstr(copy))) {
            ui_show(app, "Verify", "Same source selected.\nRead blank into a new\nfile; select that copy.", false);
        } else {
            DiagSavedComparison comparison;
            DiagFileStatus status = lf ? diag_files_compare_saved_rfid(app->storage, app->workflow.source_path,
                furi_string_get_cstr(copy), &comparison, app->message) :
                diag_files_compare_saved_nfc(app->storage, app->workflow.source_path,
                furi_string_get_cstr(copy), &comparison, app->message);
            if(status == DiagFileStatusOk) {
                furi_string_printf(app->text, "Saved decoded data:\n%s\nSource read: %s\nCopy read: %s\n\n%s\n\nDoes not prove reader\nacceptance or physical\ncard authenticity.\nTest on your own reader.",
                    comparison.equal ? "EQUAL" : "DIFFERENT", completeness(comparison.left_completeness),
                    completeness(comparison.right_completeness), comparison.detail);
                if(app->has_current) diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage,
                    comparison.equal ? "Workflow saved-data comparison equal; physical reader acceptance untested" :
                                       "Workflow saved-data comparison different; copy not verified");
                ui_show(app, "Saved copy check", furi_string_get_cstr(app->text), false);
            } else ui_show(app, "Verify failed", furi_string_get_cstr(app->message), false);
        }
    }
    furi_string_free(copy);
}
static void handoff_prepare(DiagApp* app, DiagWorkflowAction action) {
    if((action == DiagWorkflowActionWriteNfc || action == DiagWorkflowActionWriteLf) && !app->source_valid) {
        ui_show(app, "No source", "Choose a complete saved\nsource file first.\nReader nonces/keys alone\ncannot reconstruct card.", false); return;
    }
    if(action == DiagWorkflowActionWriteNfc || action == DiagWorkflowActionWriteLf) {
        if(!workflow_restore_source(app)) {
            ui_show(app, "Source unavailable", furi_string_get_cstr(app->message), false); return;
        }
        bool supported = action == DiagWorkflowActionWriteNfc ? app->source_caps.is_nfc &&
            (app->source_caps.can_native_write || app->source_caps.can_magic_write) :
            app->source_caps.is_lf && app->source_caps.can_native_write;
        if(!supported) { ui_show(app, "Write unavailable", app->source_caps.limitation, false); return; }
    }
    if(action == DiagWorkflowActionMfkey) {
        DiagNonceLibraryInfo info;
        if(!diag_reader_library_info(app->storage, &info, app->message) || !info.valid_pair_lines) {
            ui_show(app, "No usable pairs", "Capture two distinct\nClassic reader attempts\nfor same UID/sector/key.\nOpen Nonce library for\nlog errors or limits.", false); return;
        }
    }
    if(action == DiagWorkflowActionWriteNfc) {
        DiagSavedComparison source;
        if(diag_files_compare_saved_nfc(app->storage, app->workflow.source_path, app->workflow.source_path,
            &source, app->message) != DiagFileStatusOk) {
            ui_show(app, "Source failed", furi_string_get_cstr(app->message), false); return;
        }
        if(source.left_completeness == DiagSavedReadCompletenessIncomplete) {
            ui_show(app, "Incomplete source", "Not all Classic blocks\nand keys were read.\nRecover authorized keys\nand Read NFC again\nbefore writing a blank.", false); return;
        }
    }
    app->confirm_action = action;
    const char* body = action == DiagWorkflowActionReadNfc || action == DiagWorkflowActionReadLf ?
        "Read and save card.\nReturn here; select File." : action == DiagWorkflowActionMfkey ?
        "Decode shared nonce log.\nThen re-read original." : action == DiagWorkflowActionPicopass ?
        "Open HID iClass tool.\nReturn here afterward." :
        "Write selected saved card\nto your compatible blank.";
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    diag_ui_step(&app->ui, "Open native tool", body, DiagUiArtCard, "", "Open", "Cancel");
    furi_mutex_release(app->ui_mutex);
}
static void handoff_execute(DiagApp* app) {
    DiagWorkflowAction action = app->confirm_action;
    const char* target = action == DiagWorkflowActionReadLf || action == DiagWorkflowActionWriteLf ? "125 kHz RFID" :
        action == DiagWorkflowActionMfkey ? EXT_PATH("apps/NFC/mfkey.fap") :
        action == DiagWorkflowActionPicopass ? EXT_PATH("apps/NFC/picopass.fap") :
        action == DiagWorkflowActionWriteNfc && app->source_caps.can_magic_write &&
            native_tool_available(app, EXT_PATH("apps/NFC/nfc_magic.fap")) ?
            EXT_PATH("apps/NFC/nfc_magic.fap") : "NFC";
    if(action == DiagWorkflowActionWriteNfc && !app->source_caps.can_native_write &&
        !native_tool_available(app, EXT_PATH("apps/NFC/nfc_magic.fap"))) {
        app->confirm_action = 0;
        ui_show(app, "Write unavailable", "Compatible tool missing.\nSource retained.", false);
        return;
    }
    FileInfo info;
    if(target[0] == '/' && storage_common_stat(app->storage, target, &info) != FSE_OK) {
        app->confirm_action = 0;
        ui_show(app, "Tool missing", "Required tool missing.\nCheck Momentum app files.\nWorkflow retained.", false); return;
    }
    Loader* loader = furi_record_open(RECORD_LOADER);
    FuriString* self = furi_string_alloc();
    if(!loader_get_application_launch_path(loader, self)) {
        ui_show(app, "Launch failed", "Cannot find own app path.\nWorkflow retained.\nNo tool launched.", false);
    } else {
        app->workflow.pending_action = action;
        if(diag_workflow_save(app->storage, &app->workflow, app->message) == DiagFileStatusOk) {
            const char* arguments = target[0] != '/' &&
                (action == DiagWorkflowActionWriteNfc || action == DiagWorkflowActionWriteLf) ?
                app->workflow.source_path : NULL;
            loader_enqueue_launch(loader, target, arguments, LoaderDeferredLaunchFlagGui);
            loader_enqueue_launch(loader, furi_string_get_cstr(self), "resume", LoaderDeferredLaunchFlagGui);
            app->leave = true;
        } else ui_show(app, "Save failed", furi_string_get_cstr(app->message), false);
    }
    app->confirm_action = 0;
    furi_string_free(self);
    furi_record_close(RECORD_LOADER);
}

static void choose_workflow_file(DiagApp* app) {
    app->file_from_workflow = true;
    if(app->workflow.band == DiagWorkflowBandLf) workflow_source(app, true);
    else if(app->workflow.band == DiagWorkflowBandNfc) workflow_source(app, false);
    else show_menu(app, MenuSaved);
}
static void select_home(DiagApp* app, size_t selected) {
    if(selected == 0) show_menu(app, MenuWorkflowStart);
    else if(selected == 1) {
        diag_workflow_init(&app->workflow, false);
        app->reader_from_workflow = true;
        app->source_valid = false;
        app->current_for_workflow = false;
        show_menu(app, MenuReader);
    } else if(selected == 2) { app->file_from_workflow = false; show_menu(app, MenuSaved); }
    else if(selected == 3) show_menu(app, MenuSessions);
    else if(selected == 4) reference(app);
    else {
        const Version* version = version_get();
        furi_string_printf(app->text, "NFC Diagnostic Suite\n2.0.1 / native C\nMomentum mntm-012\nBuild: %.12s\nRuntime: %s\nCommit: %s\n\nNFC + 125 kHz RFID\nNo RSSI or waveforms.", DIAG_FIRMWARE_BUILD,
            version_get_version(version), version_get_githash(version));
        ui_show(app, "About", furi_string_get_cstr(app->text), false);
    }
}
static bool workflow_restore_source(DiagApp* app) {
    app->source_valid = false;
    app->current_for_workflow = false;
    if(!app->workflow.source_path[0]) return true;
    if(!ensure_current(app)) return false;
    DiagFileStatus status = app->workflow.band == DiagWorkflowBandLf ?
        diag_files_validate_rfid(app->storage, app->workflow.source_path, app->current, app->message) :
        diag_files_validate_nfc(app->storage, app->workflow.source_path, app->current, app->message);
    if(status != DiagFileStatusOk) return false;
    app->has_current = true;
    app->last_radio = RadioNone;
    app->save_xp_given = true;
    app->source_caps = diag_capabilities_for(app->current);
    app->source_valid = true;
    app->current_for_workflow = true;
    return true;
}
static void select_item(DiagApp* app, size_t selected) {
    if(app->menu == MenuHome) { select_home(app, selected); return; }
    if(app->menu == MenuSaved) {
        if(app->file_from_workflow) workflow_source(app, selected == 1);
        else browse(app, selected == 1 ? 2 : 1);
        return;
    }
    if(app->menu == MenuSessions) {
        if(selected == 0) browse(app, 0);
        else if(selected == 1) {
            app->has_baseline = app->has_current && diag_model_observe(app->current, &app->baseline);
            if(app->has_baseline) snprintf(app->baseline_timestamp, sizeof(app->baseline_timestamp), "%s", app->current->timestamp);
            ui_show(app, "Reference", app->has_baseline ? "Current session retained\nfor comparison." : "Read or open a session first.", false);
        } else if(selected == 2) compare(app);
        else if(selected == 3) {
            bool lf = app->last_card_band == DiagWorkflowBandLf;
            if(lf) start_lf(app, DiagLfModeCard, true);
            else start(app, true);
        } else if(selected == 4) logs(app, false);
        else diagnose(app);
        return;
    }
    if(app->menu == MenuReader) {
        unsigned action = app->reader_actions[selected];
        if(action == 0) start_lf(app, DiagLfModeReaderBoth, false);
        else if(action == 1) start_reader(app, DiagReaderModeField);
        else if(action == 2) start_reader(app, DiagReaderModeTypeA);
        else if(action == 3) start_reader(app, DiagReaderModeClassic);
        else if(action == 4) start_lf(app, DiagLfModeReader, false);
        else if(app->last_reader_band_report) lf_report(app);
        else reader_report(app);
        return;
    }
    if(app->menu == MenuWorkflowStart) {
        diag_workflow_init(&app->workflow, selected == 0);
        app->source_valid = false;
        app->current_for_workflow = false;
        app->reader_from_workflow = true;
        app->step = selected == 0 ? StepCardReady : StepReaderReady;
        persist_workflow(app, false);
        refresh_library(app);
        workflow_page(app);
        return;
    }
    if(selected >= app->workflow_action_count) return;
    unsigned action = app->workflow_actions[selected];
    switch(action) {
    case 0: if(app->has_current) results(app); else diagnose(app); break;
    case 1:
        app->workflow.source_path[0] = 0;
        memset(&app->workflow.identity, 0, sizeof(app->workflow.identity));
        app->workflow.band = DiagWorkflowBandUnknown;
        app->source_valid = false;
        app->menu = MenuWorkflow;
        persist_workflow(app, false);
        start(app, false); app->auto_band = app->active; break;
    case 2: app->reader_from_workflow = true; show_menu(app, MenuReader); break;
    case 3: handoff_prepare(app, DiagWorkflowActionReadNfc); break;
    case 4: handoff_prepare(app, DiagWorkflowActionReadLf); break;
    case 5: workflow_source(app, false); break;
    case 6: workflow_source(app, true); break;
    case 7: start_reader(app, DiagReaderModeClassic); break;
    case 8: handoff_prepare(app, DiagWorkflowActionMfkey); break;
    case 9: handoff_prepare(app, DiagWorkflowActionWriteNfc); break;
    case 10: handoff_prepare(app, DiagWorkflowActionWriteLf); break;
    case 11: workflow_verify(app); break;
    case 12: save(app); break;
    case 13: show_menu(app, MenuWorkflowStart); break;
    case 14: handoff_prepare(app, DiagWorkflowActionPicopass); break;
    case 15: nonce_library(app); break;
    default: break;
    }
}
static void step_action(DiagApp* app, InputKey key) {
    if(key == InputKeyLeft) {
        if(app->step == StepVerifyCopy) workflow_verify(app);
        else choose_workflow_file(app);
        return;
    }
    if(key == InputKeyRight) {
        if(app->step == StepOutcome && app->last_radio == RadioLfReader) show_menu(app, MenuReader);
        else show_menu(app, MenuWorkflowTools);
        return;
    }
    if(key != InputKeyOk) return;
    if(app->step == StepCardReady) { start(app, false); app->auto_band = app->active; }
    else if(app->step == StepReaderReady) start_lf(app, DiagLfModeReaderBoth, false);
    else if(app->step == StepChooseFile) choose_workflow_file(app);
    else if(app->step == StepVerifyCopy) workflow_verify(app);
    else if(app->step == StepReread) handoff_prepare(app, DiagWorkflowActionReadNfc);
    else if(app->step == StepSaved) show_menu(app, MenuHome);
    else save(app);
}

int32_t nfc_diagnostic_suite_app(void* argument) {
    if(memmgr_get_free_heap() < sizeof(DiagApp) + 12u * 1024u ||
       memmgr_heap_get_max_free_block() < sizeof(DiagApp)) {
        DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
        DialogMessage* message = dialog_message_alloc();
        dialog_message_set_text(message, "Insufficient free RAM.\nRestart Flipper; retry.", 64, 30, AlignCenter, AlignCenter);
        dialog_message_set_buttons(message, "Back", NULL, NULL);
        dialog_message_show(dialogs, message);
        dialog_message_free(message);
        furi_record_close(RECORD_DIALOGS);
        return -1;
    }
    DiagApp* app = calloc(1, sizeof(DiagApp));
    if(!app) return -1;
    app->ui_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->inputs = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->text = furi_string_alloc();
    app->message = furi_string_alloc();
    app->gui = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->dialogs = furi_record_open(RECORD_DIALOGS);
    app->viewport = view_port_alloc();
    show_menu(app, MenuHome);
    if(argument && !strcmp(argument, "resume")) {
        if(diag_workflow_load(app->storage, &app->workflow, app->message) == DiagFileStatusOk) {
            show_menu(app, MenuWorkflow);
            bool restored = workflow_restore_source(app);
            refresh_library(app);
            uint32_t returned = app->workflow.pending_action;
            app->workflow.pending_action = 0;
            bool updated = persist_workflow(app, true);
            if(!updated) { /* Error screen retained. */ }
            else if(restored) workflow_guide(app, returned);
            else ui_show(app, "Source unavailable", "Source changed/missing.\nChoose source again.\nNative tool return does\nnot establish success.", false);
        } else ui_show(app, "Resume failed", furi_string_get_cstr(app->message), false);
    }
    view_port_draw_callback_set(app->viewport, draw, app);
    view_port_input_callback_set(app->viewport, input, app);
    gui_add_view_port(app->gui, app->viewport, GuiLayerFullscreen);
    bool quit = false;
    while(!quit && !app->leave) {
        InputEvent event;
        if(furi_message_queue_get(app->inputs, &event, 100) == FuriStatusOk) {
            if(app->active) {
                if(event.key == InputKeyBack && app->ui.log_view) {
                    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
                    app->ui.log_view = false;
                    furi_mutex_release(app->ui_mutex);
                } else if(event.key == InputKeyBack || event.key == InputKeyLeft) {
                    app->pending_file = event.key == InputKeyLeft;
                    cancel_radio(app);
                    app->cancelled = true;
                    app->auto_band = false;
                    app->repeat = false;
                } else if(event.key == InputKeyRight) {
                    app->log_follow = true;
                    logs(app, false);
                } else if(app->ui.log_view && (event.key == InputKeyUp || event.key == InputKeyDown)) {
                    app->log_follow = false;
                    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
                    diag_ui_move(&app->ui, event.key == InputKeyUp ? -1 : 1);
                    furi_mutex_release(app->ui_mutex);
                    logs(app, true);
                }
            } else if(event.key == InputKeyBack) {
                app->showing_reference = false;
                if(app->confirm_action) { app->confirm_action = 0; workflow_page(app); }
                else if(app->ui.menu) {
                    if(app->menu == MenuHome) quit = true;
                    else if(app->menu == MenuWorkflowTools || app->menu == MenuReader ||
                            (app->menu == MenuSaved && app->file_from_workflow)) workflow_page(app);
                    else show_menu(app, MenuHome);
                } else if(app->ui.step) show_menu(app, MenuHome);
                else show_menu(app, app->menu);
            } else if(app->confirm_action) {
                if(event.key == InputKeyOk) handoff_execute(app);
                else if(event.key == InputKeyRight) workflow_page(app);
            } else if(app->showing_reference && (event.key == InputKeyLeft || event.key == InputKeyRight)) {
                app->reference = (app->reference + (event.key == InputKeyLeft ? DIAG_PROTOCOL_COUNT - 1 : 1)) % DIAG_PROTOCOL_COUNT;
                reference(app);
            } else if(app->ui.step) step_action(app, event.key);
            else {
                bool is_menu;
                size_t selected;
                furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
                is_menu = app->ui.menu;
                selected = app->ui.selected;
                if(event.key == InputKeyUp || event.key == InputKeyDown)
                    diag_ui_move(&app->ui, event.key == InputKeyUp ? -1 : 1);
                furi_mutex_release(app->ui_mutex);
                if(is_menu && event.key == InputKeyOk) select_item(app, selected);
                else if(app->ui.log_view) logs(app, true);
            }
        }
        if(app->active) {
            bool running = radio_running(app);
            if(running) { stream_logs(app); visit_radio(app, live_preview, app); }
            else if(!ensure_current(app)) {
                app->active = false;
                release_radio(app);
                discard_observations(app);
            } else {
                /* Native operation has drained; copy final evidence only now. */
                snapshot_radio(app);
                while(stream_logs(app)) {}
                app->has_current = true;
                if(app->current->identity.present && (app->radio == RadioNfc || app->radio == RadioLfCard))
                    app->last_card_band = app->radio == RadioNfc ? DiagWorkflowBandNfc : DiagWorkflowBandLf;
                app->current_for_workflow = app->workflow_radio &&
                    (app->radio == RadioNfc || app->radio == RadioLfCard);
                if(app->current->run_succeeded && !app->success_xp_given) {
                    if(app->radio == RadioNfc) dolphin_deed(DolphinDeedNfcReadSuccess);
                    else if(app->radio == RadioLfCard) dolphin_deed(DolphinDeedRfidReadSuccess);
                    else if(app->radio == RadioReader && app->reader_stats.nonce_pairs)
                        dolphin_deed(DolphinDeedNfcDetectReader);
                    app->success_xp_given = true;
                }
                if(app->auto_band && app->radio == RadioNfc && !app->current->identity.present && !app->cancelled) {
                    char previous[DIAG_LOG_MESSAGE_CAPACITY];
                    snprintf(previous, sizeof(previous), "NFC no identity: stage=%s error=%.24s/%ld; then LF",
                        diag_stage_name(app->current->last_successful_stage), app->current->error.domain,
                        (long)app->current->error.code);
                    start_lf(app, DiagLfModeCard, false);
                    snprintf(app->fallback_detail, sizeof(app->fallback_detail), "%s", previous);
                    continue;
                }
                if(app->workflow.started && app->workflow_radio && app->current->identity.present &&
                    (app->radio == RadioNfc || app->radio == RadioLfCard)) {
                    if(!app->source_valid) {
                        app->workflow.band = app->radio == RadioNfc ? DiagWorkflowBandNfc : DiagWorkflowBandLf;
                        app->workflow.identity = app->current->iso_a;
                    }
                    persist_workflow(app, false);
                }
                if(app->repeat && app->observations) {
                    bool observed = diag_model_observe(app->current, &app->observations[app->completed_runs]);
                    if(observed) app->completed_runs++;
                    if(observed && app->completed_runs < DIAG_REPEATABILITY_RUNS) {
                        app->serial_log_count = 0;
                        discard_current(app);
                        app->active = app->radio == RadioLfCard ? diag_lf_start(app->lf, DiagLfModeCard) : diag_nfc_start(app->nfc);
                        if(!app->active) {
                            release_radio(app);
                            discard_observations(app);
                            ui_show(app, "Repeat stopped", "Radio restart failed.\nRepeat not completed.", false);
                        }
                    } else {
                        app->active = false;
                        app->repeat = false;
                        app->last_radio = app->radio;
                        release_radio(app);
                        if(observed) repeat_results(app);
                        else ui_show(app, "Repeat stopped", "Could not record run.\nLast session retained.", false);
                        discard_observations(app);
                    }
                } else {
                    app->active = false;
                    app->last_radio = app->radio;
                    if(app->fallback_detail[0]) diag_model_add_log(app->current, DiagLogInfo, app->current->last_successful_stage, app->fallback_detail);
                    if(app->radio == RadioReader) {
                        app->reader_stats_valid = true;
                        app->reader_success = app->current->run_succeeded;
                        app->library_pairs_available |= app->reader_stats.pairs_saved || app->reader_stats.pairs_already_saved;
                        app->last_reader_band_report = false;
                        if(app->workflow.started && app->workflow_radio && !app->source_valid &&
                            (app->reader_stats.field_observed || app->reader_stats.selection_count || app->reader_stats.transcripts_collected)) {
                            app->workflow.band = DiagWorkflowBandNfc;
                            persist_workflow(app, false);
                        }
                    } else if(app->radio == RadioLfReader) {
                        app->lf_reader_stats_valid = true;
                        app->last_reader_band_report = true;
                        if(app->workflow.started && app->workflow_radio && !app->source_valid &&
                            app->lf_stats.field_seen != app->lf_stats.nfc_field_seen) {
                            app->workflow.band = app->lf_stats.field_seen ? DiagWorkflowBandLf : DiagWorkflowBandNfc;
                            persist_workflow(app, false);
                        }
                    }
                    append_reader_summary(app);
                    release_radio(app);
                    discard_observations(app);
                    app->step = StepOutcome;
                    workflow_page(app);
                    if(app->pending_file) { app->pending_file = false; choose_workflow_file(app); }
                }
            }
        }
        view_port_update(app->viewport);
    }
    release_radio(app);
    discard_current(app);
    discard_observations(app);
    view_port_enabled_set(app->viewport, false);
    gui_remove_view_port(app->gui, app->viewport);
    view_port_free(app->viewport);
    furi_record_close(RECORD_DIALOGS);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_GUI);
    furi_string_free(app->message);
    furi_string_free(app->text);
    furi_message_queue_free(app->inputs);
    furi_mutex_free(app->ui_mutex);
    free(app);
    return 0;
}
