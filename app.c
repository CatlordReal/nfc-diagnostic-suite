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
typedef enum { MenuHome, MenuReader, MenuWorkflowStart, MenuWorkflow } DiagMenu;
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
    DiagMenu menu;
    size_t menu_positions[4];
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
    DiagModel current;
    DiagModel baseline;
    bool has_current;
    bool has_baseline;
    bool active;
    bool usb_logs;
    bool show_live_log;
    bool log_follow;
    bool repeat;
    bool success_xp_given;
    bool save_xp_given;
    size_t completed_runs;
    size_t serial_log_count;
    size_t reference;
    DiagObservation observations[DIAG_REPEATABILITY_RUNS];
    FuriString* text;
    FuriString* message;
} DiagApp;

static void ui_show(DiagApp* app, const char* title, const char* text, bool preserve) {
    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
    app->ui.scanning = app->active;
    diag_ui_text(&app->ui, title, text, preserve);
    furi_mutex_release(app->ui_mutex);
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
static void reader_report(DiagApp* app);
static void lf_report(DiagApp* app);
static void results(DiagApp* app) {
    if(app->last_radio == RadioReader) { reader_report(app); return; }
    if(app->last_radio == RadioLfReader) { lf_report(app); return; }
    furi_string_reset(app->text);
    if(!app->has_current) {
        ui_show(app, "Results", "No session.\nChoose Identify card.", false);
        return;
    }
    const DiagModel* model = &app->current;
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
    furi_string_cat_str(app->text, "\nProtocol evidence:\n");
    for(unsigned i = 0; i < DIAG_PROTOCOL_COUNT; i++) {
        if((model->protocol_candidates | model->protocols_confirmed) & (1u << i))
            furi_string_cat_printf(app->text, "%s\n  %s\n", diag_protocol_name(i),
                model->protocols_confirmed & (1u << i) ?
                    model->provenance == DiagProvenanceSaved ? "Recorded confirmation" : "Command confirmed" : "Candidate only");
    }
    furi_string_cat_printf(app->text, "\nProduct: %s\nVersion: %s\n", model->metadata.product,
                           model->metadata.version);
    furi_string_cat_str(app->text, "No authenticity proof.\nInspection is read-only.\nBack: menu");
    ui_show(app, "Results", furi_string_get_cstr(app->text), false);
}
static void logs(DiagApp* app, bool preserve) {
    furi_string_reset(app->text);
    if(!app->has_current) furi_string_set(app->text, "No events yet.");
    for(size_t i = 0; i < app->current.log_count; i++) {
        const DiagLogEntry* log = &app->current.logs[i];
        furi_string_cat_printf(app->text, "%lu ms %s\n%s\n", (unsigned long)log->elapsed_ms,
                               diag_log_level_name(log->level), log->message);
    }
    furi_string_cat_printf(app->text, "\nDropped old events: %u\nUp/Down: scroll\nBack: menu / cancel", (unsigned)app->current.logs_dropped);
    ui_show(app, "Live log", furi_string_get_cstr(app->text), preserve);
    if(app->active && app->log_follow) {
        furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
        app->ui.scroll = app->ui.line_count > 5 ? app->ui.line_count - 5 : 0;
        furi_mutex_release(app->ui_mutex);
    }
}
static void diagnose(DiagApp* app) {
    if(!app->has_current) {
        ui_show(app, "Diagnose", "No session.\nChoose Identify card.", false);
        return;
    }
    furi_string_printf(app->text, "Last successful stage:\n%s\n", diag_stage_name(app->current.last_successful_stage));
    if(app->current.error.present) furi_string_cat_printf(app->text, "Error: %s\nCode: %ld\n",
        app->current.error.domain, (long)app->current.error.code);
    furi_string_cat_printf(app->text, "\n%s\n\nLikely causes only;\nnot measurements.\nNo RSSI, range,\nantenna tuning or\nRF waveform API.\nBack: menu",
                           diag_stage_advice(app->current.last_successful_stage));
    ui_show(app, "Diagnose", furi_string_get_cstr(app->text), false);
}
static void reference(DiagApp* app) {
    const DiagProtocolReference* entry = diag_protocol_reference(app->reference);
    furi_string_printf(app->text, "%s\n%s\n%s\n\n%s\n\nLeft/Right: protocol\nBack: menu",
        entry->name, entry->family, entry->standard, entry->diagnostic_note);
    ui_show(app, "Reference", furi_string_get_cstr(app->text), false);
}
static void save(DiagApp* app) {
    if(!app->has_current) {
        ui_show(app, "Save", "No session to save.", false);
        return;
    }
    char stamp[32];
    DiagFilesExportResult exported;
    timestamp(stamp, sizeof(stamp), true);
    DiagFileStatus status = diag_files_export_reports(app->storage, REPORT_DIR, stamp, &app->current,
        &exported, app->message);
    if(status != DiagFileStatusOk) {
        ui_show(app, "Export failed", furi_string_get_cstr(app->message), false);
        return;
    }
    status = diag_files_save_session(app->storage, exported.session_path, &app->current, app->message);
    if(status == DiagFileStatusOk && app->current.provenance == DiagProvenanceLive &&
       app->current.run_succeeded && app->current.identity.present &&
       (app->last_radio == RadioNfc || app->last_radio == RadioLfCard) && !app->save_xp_given) {
        dolphin_deed(app->current.identity.protocol == DiagProtocolLfRfid ? DolphinDeedRfidSave : DolphinDeedNfcSave);
        app->save_xp_given = true;
    }
    furi_string_printf(app->text, "%s\nJSON + CSV exported.\n%s\n%s\nSession: %s\n\nSD/apps_data/\nnfc_diagnostic_suite\nRTC time; no timezone.\nFiles contain UIDs.\nBack: menu",
        status == DiagFileStatusOk ? "Saved" : "Partial save", exported.json_path, exported.csv_path,
        status == DiagFileStatusOk ? "saved (.nds)" : furi_string_get_cstr(app->message));
    ui_show(app, "Save + export", furi_string_get_cstr(app->text), false);
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
    if(chosen) {
        DiagFileStatus status = nfc_file ?
            diag_files_validate_nfc(app->storage, furi_string_get_cstr(path), &app->current, app->message) : lf_file ?
            diag_files_validate_rfid(app->storage, furi_string_get_cstr(path), &app->current, app->message) :
            diag_files_load_session(app->storage, furi_string_get_cstr(path), &app->current, app->message);
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
    DiagComparison result = diag_model_compare(&app->baseline, &app->current);
    furi_string_printf(app->text, "Baseline: %s\nCurrent: %s\nIdentity: %s\nProtocols: %s\nMetadata: %s\nOutcome: %s\n\nCompares diagnostic\nidentity and metadata;\nnot card contents.\nMissing data is not\nproof of equality.\nBack: menu",
        app->baseline.timestamp, app->current.timestamp,
        result.identity_same ? "same" : "different / absent",
        result.protocols_same ? "same" : "different",
        result.metadata_same ? "same" : "different / absent",
        result.outcome_same ? "same" : "different");
    char evidence[96];
    snprintf(evidence, sizeof(evidence), "Comparison: identity=%s protocol=%s metadata=%s outcome=%s",
        result.identity_same ? "same" : "diff", result.protocols_same ? "same" : "diff",
        result.metadata_same ? "same" : "diff", result.outcome_same ? "same" : "diff");
    diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, evidence);
    ui_show(app, "Comparison", furi_string_get_cstr(app->text), false);
}
static void repeat_results(DiagApp* app) {
    DiagRepeatability result;
    if(!diag_observations_analyze(app->observations, &result)) {
        ui_show(app, "Repeat test", "Invalid observations.", false);
        return;
    }
    furi_string_printf(app->text, "%u runs\nSuccess: %u  Fail: %u\nIdentity: %s\nProtocols: %s\nMetadata: %s\nOutcome: %s\n\nFailures included.\nKeep one card still.\nUID randomization or\ncard movement can\nchange results.\nSave exports last run\nwith repeat summary.\nBack: menu",
        (unsigned)result.run_count, (unsigned)result.successful_runs, (unsigned)result.failed_runs,
        result.identity_repeatable ? "stable" : "unstable / absent",
        result.protocols_repeatable ? "stable" : "unstable / absent",
        result.metadata_repeatable ? "stable" : "unstable / absent",
        result.outcome_repeatable ? "stable" : "unstable");
    uint32_t elapsed = app->current.log_count ? app->current.logs[app->current.log_count - 1].elapsed_ms : 0;
    for(size_t i = 0; i < DIAG_REPEATABILITY_RUNS; i++) {
        const DiagObservation* observation = &app->observations[i];
        char detail[DIAG_LOG_MESSAGE_CAPACITY];
        snprintf(detail, sizeof(detail), "Run %u: %s; stage=%s; candidate=%04lX confirmed=%04lX",
            (unsigned)i + 1, observation->run_succeeded ? "pass" : "fail",
            diag_stage_name(observation->last_successful_stage),
            (unsigned long)observation->protocol_candidates, (unsigned long)observation->protocols_confirmed);
        diag_model_add_log_at(&app->current, DiagLogInfo, app->current.last_successful_stage, elapsed, detail);
        size_t used = (size_t)snprintf(detail, sizeof(detail), "Run %u UID=", (unsigned)i + 1);
        if(observation->identity.present) {
            for(size_t j = 0; j < observation->identity.uid_size && used + 3 < sizeof(detail); j++)
                used += (size_t)snprintf(detail + used, sizeof(detail) - used, "%02X", observation->identity.uid[j]);
        } else snprintf(detail + used, sizeof(detail) - used, "unavailable");
        diag_model_add_log_at(&app->current, DiagLogInfo, app->current.last_successful_stage, elapsed, detail);
        if(observation->metadata.product[0]) {
            snprintf(detail, sizeof(detail), "Run %u product=%s", (unsigned)i + 1, observation->metadata.product);
            diag_model_add_log_at(&app->current, DiagLogInfo, app->current.last_successful_stage, elapsed, detail);
        }
        if(observation->metadata.version[0]) {
            snprintf(detail, sizeof(detail), "Run %u version=%s", (unsigned)i + 1, observation->metadata.version);
            diag_model_add_log_at(&app->current, DiagLogInfo, app->current.last_successful_stage, elapsed, detail);
        }
        if(observation->error.present) {
            snprintf(detail, sizeof(detail), "Run %u error=%s code=%ld", (unsigned)i + 1,
                observation->error.domain, (long)observation->error.code);
            diag_model_add_log_at(&app->current, DiagLogWarning, app->current.last_successful_stage, elapsed, detail);
        }
    }
    char summary[96];
    snprintf(summary, sizeof(summary), "Repeat: %u/5 passed; UID=%s protocol=%s metadata=%s",
        (unsigned)result.successful_runs, result.identity_repeatable ? "stable" : "varies",
        result.protocols_repeatable ? "stable" : "varies", result.metadata_repeatable ? "stable" : "varies");
    diag_model_add_log_at(&app->current, DiagLogInfo, app->current.last_successful_stage, elapsed, summary);
    ui_show(app, "Repeat test", furi_string_get_cstr(app->text), false);
}
static void release_radio(DiagApp* app) {
    diag_nfc_free(app->nfc); app->nfc = NULL;
    diag_lf_free(app->lf); app->lf = NULL;
    diag_reader_free(app->reader); app->reader = NULL;
    app->radio = RadioNone;
}
static bool workflow_context(DiagApp* app) {
    return app->menu == MenuWorkflow || (app->menu == MenuReader && app->reader_from_workflow);
}
static bool persist_workflow(DiagApp* app, bool show_error) {
    bool saved = diag_workflow_save(app->storage, &app->workflow, app->message) == DiagFileStatusOk;
    app->workflow_save_failed = !saved;
    if(!saved) {
        if(app->has_current) diag_model_add_log(&app->current, DiagLogError, app->current.last_successful_stage,
            "Workflow save failed; radio evidence retained; disk progress may be older");
        if(show_error) ui_show(app, "Workflow save failed", furi_string_get_cstr(app->message), false);
    }
    return saved;
}
static bool radio_memory(DiagApp* app, bool card_reader) {
    /* Reserve includes one engine/model, stacks, native data and RX buffers. */
    size_t needed = card_reader ? 40u * 1024u : 24u * 1024u;
    if(memmgr_get_free_heap() >= needed && memmgr_heap_get_max_free_block() >= 12u * 1024u) return true;
    furi_string_printf(app->text, "Free RAM: %u bytes\nNeed reserve: %u\nLargest block: %u\nClose other tools or\nrestart Flipper; retry.\nRadio not started.",
        (unsigned)memmgr_get_free_heap(), (unsigned)needed, (unsigned)memmgr_heap_get_max_free_block());
    ui_show(app, "Low memory", furi_string_get_cstr(app->text), false);
    return false;
}
static void start(DiagApp* app, bool repeat) {
    release_radio(app);
    app->active = false;
    app->workflow_radio = workflow_context(app);
    app->current_for_workflow = false;
    if(!radio_memory(app, true)) return;
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
    app->show_live_log = true;
    app->log_follow = true;
    app->active = diag_nfc_start(app->nfc);
    app->has_current = app->active;
    if(app->active) {
        dolphin_deed(DolphinDeedNfcRead);
        ui_show(app, "Scanning", "Hold one card near\nFlipper's NFC antenna.\n\nUp/Down: live log\nBack: cancel", false);
    } else ui_show(app, "Busy", "NFC worker draining.\nTry after it stops.", false);
}
static DiagCapabilities workflow_capabilities(DiagApp* app) {
    if(app->source_valid) return app->source_caps;
    if(!app->current_for_workflow) return diag_capabilities_for(NULL);
    DiagCapabilities caps = diag_capabilities_for(app->has_current ? &app->current : NULL);
    if((app->workflow.band == DiagWorkflowBandNfc && caps.is_nfc) ||
       (app->workflow.band == DiagWorkflowBandLf && caps.is_lf)) return caps;
    return diag_capabilities_for(NULL);
}
static void show_menu(DiagApp* app, DiagMenu menu) {
    app->menu_positions[app->menu] = app->ui.selected;
    app->menu = menu;
    app->confirm_action = 0;
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
        diag_ui_menu(&app->ui, "Reader diagnostics", app->reader_labels, count);
    }
    else if(menu == MenuWorkflowStart) diag_ui_menu(&app->ui, "Card workflow", diag_workflow_start_items, ITEM_COUNT(diag_workflow_start_items));
    else if(menu == MenuWorkflow) {
        DiagCapabilities caps = workflow_capabilities(app);
        bool pairs = app->library_pairs_available;
        app->workflow_action_count = diag_capabilities_workflow_actions(caps, app->workflow.band,
            app->workflow.have_card, app->source_valid, pairs, app->workflow_actions, ITEM_COUNT(app->workflow_actions));
        for(size_t i = 0; i < app->workflow_action_count; ++i)
            app->workflow_labels[i] = diag_workflow_menu_items[app->workflow_actions[i]];
        diag_ui_menu(&app->ui, "Card workflow", app->workflow_labels, app->workflow_action_count);
    }
    else diag_ui_menu(&app->ui, "NFC Diagnostic Suite", diag_menu_items, DIAG_MENU_COUNT);
    size_t selected = app->menu_positions[menu];
    app->ui.selected = selected < app->ui.menu_count ? selected : app->ui.menu_count - 1;
    furi_mutex_release(app->ui_mutex);
}
static void snapshot_radio(DiagApp* app) {
    if(app->radio == RadioNfc) diag_nfc_snapshot(app->nfc, &app->current);
    else if(app->radio == RadioReader) diag_reader_snapshot(app->reader, &app->current, &app->reader_stats);
    else if(app->radio == RadioLfCard || app->radio == RadioLfReader)
        diag_lf_snapshot(app->lf, &app->current, &app->lf_stats);
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
    app->workflow_radio = workflow_context(app);
    app->current_for_workflow = false;
    app->repeat = false;
    app->auto_band = false;
    app->fallback_detail[0] = 0;
    app->cancelled = false;
    app->success_xp_given = false;
    app->save_xp_given = false;
    app->serial_log_count = 0;
    app->show_live_log = true;
    app->log_follow = true;
}
static void start_lf(DiagApp* app, DiagLfMode mode) {
    prepare_run(app);
    if(!radio_memory(app, mode == DiagLfModeCard)) return;
    app->lf = diag_lf_alloc();
    app->radio = mode == DiagLfModeCard ? RadioLfCard : RadioLfReader;
    app->active = diag_lf_start(app->lf, mode);
    app->has_current = app->active;
    if(app->active) {
        if(mode == DiagLfModeCard) dolphin_deed(DolphinDeedRfidRead);
        ui_show(app, mode == DiagLfModeCard ? "Scan 125 kHz" : "Reader fields",
            mode == DiagLfModeCard ? "Hold one LF card near\nFlipper's LF antenna.\nNative ASK/PSK decode.\n25 second limit.\nBack: cancel" :
            "Hold Flipper near\nyour reader.\nPassive field samples.\n25 second limit.\nBack: stop", false);
    } else ui_show(app, "Start failed", "LF worker unavailable.\nRadio not started.", false);
}
static void start_reader(DiagApp* app, DiagReaderMode mode) {
    DiagIsoAIdentity identity = {0};
    if(workflow_context(app)) {
        if(app->workflow.identity.present) identity = app->workflow.identity;
    } else if(app->has_current) identity = app->current.iso_a;
    prepare_run(app);
    if(!radio_memory(app, mode == DiagReaderModeClassic)) return;
    app->reader = diag_reader_alloc();
    app->radio = RadioReader;
    app->active = diag_reader_start(app->reader, mode, identity.present ? &identity : NULL);
    app->has_current = app->active;
    if(app->active) ui_show(app, diag_reader_mode_name(mode),
        mode == DiagReaderModeField ? "Hold near NFC reader.\n10 ms field samples.\nNo reader identity or\nsignal strength.\nBack: stop" :
        identity.present ? "Present Flipper to\nyour test reader.\nUsing selected card UID.\n30 second limit.\nBack: stop" :
        "Diagnostic test UID.\nReader may ignore it.\nPresent to own reader.\n30 second limit.\nBack: stop", false);
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
    furi_string_cat_printf(app->text, "Errors: %lu\nLost events: %lu\nStorage error: %ld\n\nNo brand identification.\nNo response may mean\nwrong protocol/UID,\nprotected reader, or\npoor coupling.\nSave + export retains\ncounters in event log.\nBack: menu",
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
        "Field frequency is LF\ncounter output; not\ncalibrated metrology.\nNo protocol or brand\nconfirmed by field.\nNo field: reader may\nbe pulsed/asleep or\nout of coupling range.\nBack: menu");
    ui_show(app, "Reader bands", furi_string_get_cstr(app->text), false);
}
static void append_reader_summary(DiagApp* app) {
    char line[DIAG_LOG_MESSAGE_CAPACITY];
    if(app->last_radio == RadioReader) {
        const DiagReaderStats* s = &app->reader_stats;
        snprintf(line, sizeof(line), "Reader stats: mode=%u errors=%lu lost=%lu elapsed=%lu ms", s->mode,
            (unsigned long)s->error_count, (unsigned long)s->events_dropped, (unsigned long)s->elapsed_ms);
        diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
        if(s->field_available) {
            snprintf(line, sizeof(line), "Field: period=%lu ms samples=%lu on/off edges=%lu/%lu",
                (unsigned long)s->sample_period_ms, (unsigned long)s->samples,
                (unsigned long)s->field_on_count, (unsigned long)s->field_off_count);
            diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
            snprintf(line, sizeof(line), "Sampled on/off durations=%lu/%lu ms", (unsigned long)s->field_on_ms, (unsigned long)s->field_off_ms);
            diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
        }
        if(s->selection_available || s->rx_total_available) {
            snprintf(line, sizeof(line), "Type A: selections=%lu RX=%lu requests=%lu gap=%lu..%lu ms",
                (unsigned long)s->selection_count, (unsigned long)s->rx_count, (unsigned long)s->request_count,
                (unsigned long)s->min_request_gap_ms, (unsigned long)s->max_request_gap_ms);
            diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
        }
        snprintf(line, sizeof(line), "Classic: transcripts=%lu duplicates=%lu rejected=%lu pairs=%lu",
            (unsigned long)s->transcripts_collected, (unsigned long)s->transcript_duplicates,
            (unsigned long)s->transcript_rejected, (unsigned long)s->nonce_pairs);
        diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
        snprintf(line, sizeof(line), "Nonce sync: saved=%lu existing=%lu storage=%ld",
            (unsigned long)s->pairs_saved, (unsigned long)s->pairs_already_saved, (long)s->storage_error);
        diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
    } else if(app->last_radio == RadioLfReader) {
        const DiagLfStats* s = &app->lf_stats;
        snprintf(line, sizeof(line), "Reader fields: period=%lu ms samples=%lu LF on/off=%lu/%lu",
            (unsigned long)s->sample_period_ms, (unsigned long)s->samples_total,
            (unsigned long)s->field_present_samples, (unsigned long)s->field_absent_samples);
        diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
        snprintf(line, sizeof(line), "LF counter Hz: last=%lu min=%lu max=%lu; no calibrated accuracy",
            (unsigned long)s->frequency_hz_last, (unsigned long)s->frequency_hz_min, (unsigned long)s->frequency_hz_max);
        diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
        if(s->mode == DiagLfModeReaderBoth) {
            snprintf(line, sizeof(line), "NFC field samples on/off=%lu/%lu; presence only, no protocol inference",
                (unsigned long)s->nfc_field_present_samples, (unsigned long)s->nfc_field_absent_samples);
            diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, line);
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
        "Momentum shared library\nSD/nfc/.mfkey32.log\nExists: %s\nBytes: %llu\nValid pair lines: %lu\nMalformed: %lu\nOversized: %lu\nScan: %s\nUser dictionary: %lu\nSystem dictionary: %lu\nDictionary scan: %s\n\n%s\nNo keys shown/deleted.\nMFKey runs on Flipper.\nRecovered keys go to\nnfc/assets/\nmf_classic_dict_user.nfc\nMIFARE Classic only.\nBack: menu",
        info.exists ? "yes" : "no", (unsigned long long)info.size_bytes, (unsigned long)info.valid_pair_lines,
        (unsigned long)info.malformed_lines, (unsigned long)info.oversized_lines,
        info.truncated ? "partial (1 MiB cap)" : "complete",
        (unsigned long)info.user_dictionary_entries, (unsigned long)info.system_dictionary_entries,
        info.user_dictionary_complete && info.system_dictionary_complete ? "complete" : "partial / absent",
        ok ? "Library read-only." : furi_string_get_cstr(app->message));
    ui_show(app, "Nonce library", furi_string_get_cstr(app->text), false);
}
static void workflow_guide(DiagApp* app, uint32_t returned) {
    DiagCapabilities caps = workflow_capabilities(app);
    furi_string_printf(app->text, "%s\nBand: %s\n", app->workflow.have_card ? "Original card available" : "Reader-only workflow",
        app->workflow.band == DiagWorkflowBandNfc ? "13.56 MHz NFC" : app->workflow.band == DiagWorkflowBandLf ? "125 kHz RFID" : "not identified");
    if(app->workflow_save_failed) furi_string_cat_str(app->text, "Workflow save failed.\nStored progress may be old.\nSee live log for details.\n\n");
    if(returned) furi_string_cat_str(app->text, "Returned from native tool.\nIts result is unverified;\nit may have been cancelled.\n\n");
    if(!app->workflow.have_card) furi_string_cat_str(app->text,
        "Start: Reader diagnostics.\nField finds band only.\nTry Type A compatibility\nif NFC. Classic capture\nneeds actual reader\nauthentication attempts.\nA diagnostic UID may be\nignored; only use your\nown enrolled test UID.\nKeys alone cannot create\na complete source card.\n\n");
    else furi_string_cat_str(app->text,
        "1 Find card (both bands).\n2 Read/save in native app.\n3 Choose saved source.\n4 Use supported blank.\n5 Read blank into new file.\n6 Verify saved copy.\n\n");
    if(caps.classic) furi_string_cat_str(app->text,
        "Classic: capture pairs,\ndecode with MFKey, then\nRead NFC again using\nshared key dictionary.\nExtract MFC Keys in\nnative NFC offers other\nfirmware recovery modes.\nRead all sectors first.\n\n");
    furi_string_cat_printf(app->text, "Compatibility:\n%s\nNative tool: %s\n\nSource: %s\n\nNo universal clone.\nDESFire/Plus protected\ncredentials need keys\nand issuer support.\nFeliCa/ISO15693/NTAG\nwrite support varies.\nPhone/rolling keys and\nUHF/2.4 GHz systems\nare unsupported.\nNative tools decide\nblank compatibility.\nTest copy on own reader.\nBack: workflow", caps.limitation, caps.native_tool,
        app->workflow.source_path[0] ? app->workflow.source_path : "not selected");
    ui_show(app, "Workflow guide", furi_string_get_cstr(app->text), false);
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
    if(choose_path(app, lf, path)) {
        DiagFileStatus status = lf ? diag_files_validate_rfid(app->storage, furi_string_get_cstr(path), &app->current, app->message) :
            diag_files_validate_nfc(app->storage, furi_string_get_cstr(path), &app->current, app->message);
        if(status == DiagFileStatusOk) {
            app->has_current = true; app->last_radio = RadioNone; app->save_xp_given = true;
            DiagWorkflow candidate = app->workflow;
            candidate.band = lf ? DiagWorkflowBandLf : DiagWorkflowBandNfc;
            candidate.identity = app->current.iso_a;
            snprintf(candidate.source_path, sizeof(candidate.source_path), "%s", furi_string_get_cstr(path));
            status = diag_workflow_save(app->storage, &candidate, app->message);
            app->workflow_save_failed = status != DiagFileStatusOk;
            if(status == DiagFileStatusOk) {
                app->workflow = candidate;
                app->source_caps = diag_capabilities_for(&app->current);
                app->source_valid = true;
                app->current_for_workflow = true;
                workflow_guide(app, 0);
            } else furi_string_cat_str(app->message, "\nPrevious workflow retained.");
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
        if(!strcmp(app->workflow.source_path, furi_string_get_cstr(copy))) {
            ui_show(app, "Verify", "Same source selected.\nRead blank into a new\nfile; select that copy.", false);
        } else {
            DiagSavedComparison comparison;
            DiagFileStatus status = lf ? diag_files_compare_saved_rfid(app->storage, app->workflow.source_path,
                furi_string_get_cstr(copy), &comparison, app->message) :
                diag_files_compare_saved_nfc(app->storage, app->workflow.source_path,
                furi_string_get_cstr(copy), &comparison, app->message);
            if(status == DiagFileStatusOk) {
                furi_string_printf(app->text, "Saved decoded data:\n%s\nSource read: %s\nCopy read: %s\n\n%s\n\nDoes not prove reader\nacceptance or physical\ncard authenticity.\nTest on your own reader.\nBack: workflow",
                    comparison.equal ? "EQUAL" : "DIFFERENT", completeness(comparison.left_completeness),
                    completeness(comparison.right_completeness), comparison.detail);
                if(app->has_current) diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage,
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
    const char* instructions = action == DiagWorkflowActionPicopass ?
        (app->workflow.have_card ? "Native HID iClass opens.\nUse Read Card. Native app\nhandles PicoPass formats.\nNo result inferred here." :
        "Native HID iClass opens.\nLoclass is its reader\ndiagnostic mode. Only\nsupported iClass readers.\nUses native app logs.") : action == DiagWorkflowActionReadNfc ?
        "Native NFC opens.\nChoose Read; save card.\nReturn, Choose source\n.nfc here. New keys in\nshared dictionary apply." : action == DiagWorkflowActionReadLf ?
        "Native 125 kHz opens.\nRead original and save.\nReturn, Choose source\n.rfid here. Native decoder\nselects supported type." : action == DiagWorkflowActionMfkey ?
        "Native MFKey opens.\nStart recovery on Flipper.\nUses shared nonce log.\nKeys save to NFC user\ndictionary; then re-read." : action == DiagWorkflowActionWriteLf ?
        "Native 125 kHz opens.\nSaved: choose source.\nWrite to compatible\nblank T5577/EM4305.\nNative app checks support." :
        "Native NFC tool opens.\nSelect saved source.\nWrite only to your blank.\nNative tool checks card.\nRe-read into a NEW file.";
    furi_string_printf(app->text, "%s\n\nSource: %s\n\nApp exits; radios release.\nReturns here afterward.\nOK: open native tool\nBack: cancel", instructions,
        app->workflow.source_path[0] ? app->workflow.source_path : "not selected");
    ui_show(app, "Native tool", furi_string_get_cstr(app->text), false);
}
static void handoff_execute(DiagApp* app) {
    DiagWorkflowAction action = app->confirm_action;
    const char* target = action == DiagWorkflowActionReadLf || action == DiagWorkflowActionWriteLf ? "125 kHz RFID" :
        action == DiagWorkflowActionMfkey ? EXT_PATH("apps/NFC/mfkey.fap") :
        action == DiagWorkflowActionPicopass ? EXT_PATH("apps/NFC/picopass.fap") :
        action == DiagWorkflowActionWriteNfc && app->source_caps.can_magic_write ?
            EXT_PATH("apps/NFC/nfc_magic.fap") : "NFC";
    FileInfo info;
    if(target[0] == '/' && storage_common_stat(app->storage, target, &info) != FSE_OK) {
        app->confirm_action = 0;
        ui_show(app, "Tool missing", "Install bundled FAPs\nto SD/apps/NFC.\nMFKey + NFC Magic\nmust match Momentum.\nWorkflow retained.", false); return;
    }
    Loader* loader = furi_record_open(RECORD_LOADER);
    FuriString* self = furi_string_alloc();
    if(!loader_get_application_launch_path(loader, self)) {
        ui_show(app, "Launch failed", "Cannot find own app path.\nWorkflow retained.\nNo tool launched.", false);
    } else {
        app->workflow.pending_action = action;
        if(diag_workflow_save(app->storage, &app->workflow, app->message) == DiagFileStatusOk) {
            loader_enqueue_launch(loader, target, NULL, LoaderDeferredLaunchFlagGui);
            loader_enqueue_launch(loader, furi_string_get_cstr(self), "resume", LoaderDeferredLaunchFlagGui);
            app->leave = true;
        } else ui_show(app, "Save failed", furi_string_get_cstr(app->message), false);
    }
    app->confirm_action = 0;
    furi_string_free(self);
    furi_record_close(RECORD_LOADER);
}

static void select_home(DiagApp* app, size_t selected) {
    switch(selected) {
    case 0: start(app, false); app->auto_band = app->active; break;
    case 1: results(app); break;
    case 2: logs(app, false); break;
    case 3: diagnose(app); break;
    case 4: save(app); break;
    case 5: browse(app, 0); break;
    case 6: browse(app, 1); break;
    case 7:
        if(app->has_current) {
            memcpy(&app->baseline, &app->current, sizeof(app->baseline));
            app->has_baseline = true;
            ui_show(app, "Baseline", "Current session set\nas comparison baseline.\nLoad/scan next card,\nthen Compare sessions.", false);
        } else ui_show(app, "Baseline", "No current session.", false);
        break;
    case 8: compare(app); break;
    case 9:
        if(app->has_current && app->current.identity.present && app->current.identity.protocol == DiagProtocolLfRfid) {
            start_lf(app, DiagLfModeCard);
            app->repeat = app->active;
            app->completed_runs = 0;
        } else start(app, true);
        break;
    case 10: reference(app); break;
    case 11: {
        app->last_radio = RadioNone;
        app->current_for_workflow = false;
        bool passed = diag_model_selftest();
        diag_model_load_simulation(&app->current, DiagSimulationCandidateOnly, 0);
        app->has_current = true;
        app->save_xp_given = true;
        ui_show(app, "Simulated tests", passed ?
            "PASS: model self-test\nSimulation loaded.\nNo NFC radio used.\nNo XP awarded.\nResults/logs available.\nNot physical RF proof." :
            "FAIL: model self-test\nCheck host test logs.\nNo NFC radio used.", false);
        break;
    }
    case 12:
        app->usb_logs = !app->usb_logs;
        ui_show(app, "USB diagnostics", app->usb_logs ?
            "Enabled: NfcDiag logs.\nUSB serial terminal:\nrun: log info\nThen launch this app.\nCtrl+C stops streaming.\nLogs contain UIDs.\nNo USB mode changes.\nSelect again: disable." :
            "Disabled.\nSelect again to enable.\nUses Momentum's USB\nserial log command.", false);
        break;
    case 14: start_lf(app, DiagLfModeCard); break;
    case 15: app->reader_from_workflow = false; show_menu(app, MenuReader); break;
    case 16: show_menu(app, MenuWorkflowStart); break;
    case 17: browse(app, 2); break;
    case 18: nonce_library(app); break;
    default: {
        const Version* version = version_get();
        furi_string_printf(app->text, "NFC Diagnostic Suite\n2.0 / native C\nMomentum API 87.1\nBuild: %.12s\nRuntime: %s\nCommit: %s\n\nNFC + 125 kHz RFID.\nNative reader tests.\nGuided native tools.\nNo signal strength or\nwaveform measurements.\nPicoPass uses separate\nHID iClass native app.\nBack: menu", DIAG_FIRMWARE_BUILD,
            version_get_version(version), version_get_githash(version));
        ui_show(app, "About", furi_string_get_cstr(app->text), false);
        break;
    }
    }
}
static bool workflow_restore_source(DiagApp* app) {
    app->source_valid = false;
    app->current_for_workflow = false;
    if(!app->workflow.source_path[0]) return true;
    DiagFileStatus status = app->workflow.band == DiagWorkflowBandLf ?
        diag_files_validate_rfid(app->storage, app->workflow.source_path, &app->current, app->message) :
        diag_files_validate_nfc(app->storage, app->workflow.source_path, &app->current, app->message);
    if(status != DiagFileStatusOk) return false;
    app->has_current = true;
    app->last_radio = RadioNone;
    app->save_xp_given = true;
    app->source_caps = diag_capabilities_for(&app->current);
    app->source_valid = true;
    app->current_for_workflow = true;
    return true;
}
static void select_item(DiagApp* app, size_t selected) {
    if(app->menu == MenuHome) { select_home(app, selected); return; }
    if(app->menu == MenuReader) {
        unsigned action = app->reader_actions[selected];
        if(action == 0) start_lf(app, DiagLfModeReaderBoth);
        else if(action == 1) start_reader(app, DiagReaderModeField);
        else if(action == 2) start_reader(app, DiagReaderModeTypeA);
        else if(action == 3) start_reader(app, DiagReaderModeClassic);
        else if(action == 4) start_lf(app, DiagLfModeReader);
        else if(app->last_reader_band_report) lf_report(app);
        else reader_report(app);
        return;
    }
    if(app->menu == MenuWorkflowStart) {
        if(selected < 2) {
            DiagWorkflow candidate;
            diag_workflow_init(&candidate, selected == 0);
            if(diag_workflow_save(app->storage, &candidate, app->message) != DiagFileStatusOk) {
                ui_show(app, "Save failed", furi_string_get_cstr(app->message), false); return;
            }
            app->workflow = candidate;
            app->workflow_save_failed = false;
            app->source_valid = false;
            app->current_for_workflow = false;
        } else {
            if(diag_workflow_load(app->storage, &app->workflow, app->message) != DiagFileStatusOk) {
                ui_show(app, "No workflow", furi_string_get_cstr(app->message), false); return;
            }
            if(!workflow_restore_source(app)) {
                show_menu(app, MenuWorkflow);
                ui_show(app, "Source unavailable", "Saved source changed,\ninvalid, or missing.\nChoose source again.\nWriting stays unavailable.", false);
                return;
            }
        }
        refresh_library(app);
        show_menu(app, MenuWorkflow);
        workflow_guide(app, 0);
        return;
    }
    if(selected >= app->workflow_action_count) return;
    unsigned action = app->workflow_actions[selected];
    switch(action) {
    case 0: workflow_guide(app, 0); break;
    case 1: {
        DiagWorkflow candidate = app->workflow;
        candidate.source_path[0] = 0;
        memset(&candidate.identity, 0, sizeof(candidate.identity));
        candidate.band = DiagWorkflowBandUnknown;
        if(diag_workflow_save(app->storage, &candidate, app->message) != DiagFileStatusOk) {
            ui_show(app, "Save failed", furi_string_get_cstr(app->message), false); break;
        }
        app->workflow = candidate;
        app->workflow_save_failed = false;
        app->source_valid = false;
        start(app, false);
        app->auto_band = app->active;
        break;
    }
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
            if(event.key == InputKeyBack) {
                if(app->active) {
                    cancel_radio(app);
                    app->cancelled = true;
                    app->auto_band = false;
                    app->repeat = false;
                    ui_show(app, "Stopping", "Cancelling radio.\nWaiting for current\nfirmware transaction.\nNo forced resource\nrelease.", false);
                } else {
                    app->confirm_action = 0;
                    if(app->ui.menu) {
                        if(app->menu == MenuHome) quit = true;
                        else show_menu(app, app->menu == MenuReader && app->reader_from_workflow ? MenuWorkflow : MenuHome);
                    } else show_menu(app, app->menu);
                }
            } else if(app->active) {
                if(event.key == InputKeyUp || event.key == InputKeyDown) {
                    app->log_follow = false;
                    logs(app, true);
                    furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
                    diag_ui_move(&app->ui, event.key == InputKeyUp ? -1 : 1);
                    size_t bottom = app->ui.line_count > 5 ? app->ui.line_count - 5 : 0;
                    if(event.key == InputKeyDown && app->ui.scroll == bottom) app->log_follow = true;
                    furi_mutex_release(app->ui_mutex);
                }
            } else {
                bool is_menu;
                size_t selected;
                furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
                is_menu = app->ui.menu;
                selected = app->ui.selected;
                if(event.key == InputKeyUp || event.key == InputKeyDown)
                    diag_ui_move(&app->ui, event.key == InputKeyUp ? -1 : 1);
                furi_mutex_release(app->ui_mutex);
                if(event.key == InputKeyOk && app->confirm_action) handoff_execute(app);
                else if(is_menu && event.key == InputKeyOk) select_item(app, selected);
                else if(!is_menu && app->menu == MenuHome && selected == 10 &&
                    (event.key == InputKeyLeft || event.key == InputKeyRight)) {
                    app->reference = (app->reference + (event.key == InputKeyLeft ? DIAG_PROTOCOL_COUNT - 1 : 1)) % DIAG_PROTOCOL_COUNT;
                    reference(app);
                }
            }
        }
        if(app->active) {
            snapshot_radio(app);
            if(app->usb_logs) {
                size_t first = app->serial_log_count > app->current.logs_dropped ?
                    app->serial_log_count - app->current.logs_dropped : 0;
                for(size_t i = first; i < app->current.log_count; i++) {
                    const DiagLogEntry* log = &app->current.logs[i];
                    FURI_LOG_I("NfcDiag", "%lu ms %s", (unsigned long)log->elapsed_ms, log->message);
                }
                app->serial_log_count = app->current.logs_dropped + app->current.log_count;
            }
            bool running = radio_running(app);
            if(running && app->show_live_log) logs(app, true);
            furi_mutex_acquire(app->ui_mutex, FuriWaitForever);
            app->ui.scanning = running;
            app->ui.animation_frame++;
            app->ui.run_number = app->repeat ? app->completed_runs + 1 : 0;
            furi_mutex_release(app->ui_mutex);
            if(!running) {
                /* Snapshot again after completion synchronizes final callback data. */
                snapshot_radio(app);
                app->current_for_workflow = app->workflow_radio &&
                    (app->radio == RadioNfc || app->radio == RadioLfCard);
                if(app->current.run_succeeded && !app->success_xp_given) {
                    if(app->radio == RadioNfc) dolphin_deed(DolphinDeedNfcReadSuccess);
                    else if(app->radio == RadioLfCard) dolphin_deed(DolphinDeedRfidReadSuccess);
                    else if(app->radio == RadioReader && app->reader_stats.nonce_pairs)
                        dolphin_deed(DolphinDeedNfcDetectReader);
                    app->success_xp_given = true;
                }
                if(app->auto_band && app->radio == RadioNfc && !app->current.identity.present && !app->cancelled) {
                    char previous[DIAG_LOG_MESSAGE_CAPACITY];
                    snprintf(previous, sizeof(previous), "NFC phase no identity: stage=%s error=%.24s/%ld; then LF",
                        diag_stage_name(app->current.last_successful_stage), app->current.error.domain,
                        (long)app->current.error.code);
                    start_lf(app, DiagLfModeCard);
                    snprintf(app->fallback_detail, sizeof(app->fallback_detail), "%s", previous);
                    continue;
                }
                if(app->workflow.started && app->workflow_radio && app->current.identity.present &&
                   (app->radio == RadioNfc || app->radio == RadioLfCard)) {
                    if(!app->source_valid) app->workflow.band = app->radio == RadioNfc ? DiagWorkflowBandNfc : DiagWorkflowBandLf;
                    if(!app->source_valid) app->workflow.identity = app->current.iso_a;
                    persist_workflow(app, false);
                }
                if(app->repeat) {
                    bool observed = diag_model_observe(&app->current, &app->observations[app->completed_runs]);
                    if(!observed) {
                        app->active = false;
                        app->repeat = false;
                        release_radio(app);
                        ui_show(app, "Repeat stopped", "Could not record run.\nLast session retained.", false);
                        continue;
                    }
                    app->completed_runs++;
                    if(app->completed_runs < DIAG_REPEATABILITY_RUNS) {
                        app->serial_log_count = 0;
                        app->active = app->radio == RadioLfCard ? diag_lf_start(app->lf, DiagLfModeCard) : diag_nfc_start(app->nfc);
                        if(!app->active) {
                            app->repeat = false;
                            release_radio(app);
                            ui_show(app, "Repeat stopped", "Radio restart failed.\nLast session retained.\nRepeat not completed.", false);
                        } else {
                            ui_show(app, "Repeat test", "Keep same card still.\nBack: cancel\nUp/Down: live log", false);
                        }
                    } else {
                        app->active = false;
                        app->repeat = false;
                        app->last_radio = app->radio;
                        release_radio(app);
                        repeat_results(app);
                    }
                } else {
                    app->active = false;
                    app->last_radio = app->radio;
                    if(app->fallback_detail[0]) diag_model_add_log(&app->current, DiagLogInfo, app->current.last_successful_stage, app->fallback_detail);
                    if(app->radio == RadioReader) {
                        app->reader_stats_valid = true;
                        app->reader_success = app->current.run_succeeded;
                        app->library_pairs_available = app->library_pairs_available || app->reader_stats.pairs_saved || app->reader_stats.pairs_already_saved;
                        app->last_reader_band_report = false;
                        if(app->workflow.started && app->workflow_radio && !app->source_valid && (app->reader_stats.field_observed || app->reader_stats.selection_count || app->reader_stats.transcripts_collected)) {
                            app->workflow.band = DiagWorkflowBandNfc;
                            persist_workflow(app, false);
                        }
                    } else if(app->radio == RadioLfReader) {
                        app->lf_reader_stats_valid = true;
                        app->last_reader_band_report = true;
                        if(app->workflow.started && app->workflow_radio && !app->source_valid && app->lf_stats.field_seen != app->lf_stats.nfc_field_seen) {
                            app->workflow.band = app->lf_stats.field_seen ? DiagWorkflowBandLf : DiagWorkflowBandNfc;
                            persist_workflow(app, false);
                        }
                    }
                    append_reader_summary(app);
                    release_radio(app);
                    results(app);
                }
            }
        }
        view_port_update(app->viewport);
    }
    release_radio(app);
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
