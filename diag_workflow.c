#include "diag_workflow.h"

#include <string.h>

#ifndef DIAG_WORKFLOW_HOST
#include <flipper_format/flipper_format.h>
#include <furi.h>
#include <storage/storage.h>
#endif

#define DIAG_WORKFLOW_FILETYPE "NFC Diagnostic Workflow"
#define DIAG_WORKFLOW_VERSION 1u
#define DIAG_WORKFLOW_MAX_FILE_SIZE 2048u
#define DIAG_WORKFLOW_DIRECTORY "/ext/apps_data/nfc_diagnostic_suite"
#define DIAG_WORKFLOW_TEMP_PATH "/ext/apps_data/nfc_diagnostic_suite/workflow.tmp"
#define DIAG_WORKFLOW_BACKUP_PATH "/ext/apps_data/nfc_diagnostic_suite/workflow.bak"

static size_t diag_workflow_bounded_strlen(const char* text, size_t capacity) {
    size_t size = 0u;
    if(!text) return capacity;
    while(size < capacity && text[size]) ++size;
    return size;
}

static bool diag_workflow_has_suffix(const char* path, const char* suffix) {
    const size_t path_size = strlen(path);
    const size_t suffix_size = strlen(suffix);
    return path_size >= suffix_size && !strcmp(path + path_size - suffix_size, suffix);
}

static bool diag_workflow_parse_bool(const char* text, bool* value) {
    if(!text || !value) return false;
    if(!strcmp(text, "true")) {
        *value = true;
        return true;
    }
    if(!strcmp(text, "false")) {
        *value = false;
        return true;
    }
    return false;
}

static bool diag_workflow_valid(const DiagWorkflow* workflow) {
    if(!workflow || (unsigned)workflow->band > DiagWorkflowBandLf ||
       workflow->pending_action > DiagWorkflowActionPicopass ||
       diag_workflow_bounded_strlen(workflow->source_path, sizeof(workflow->source_path)) >=
           sizeof(workflow->source_path)) {
        return false;
    }
    const size_t uid_size = workflow->identity.uid_size;
    const bool uid_size_valid =
        uid_size == 0u || uid_size == 4u || uid_size == 7u || uid_size == 10u;
    if(!uid_size_valid || workflow->identity.present != (uid_size != 0u)) return false;
    if(workflow->identity.present) {
        const uint8_t expected_cascade = uid_size == 4u ? 1u : (uid_size == 7u ? 2u : 3u);
        if(workflow->band != DiagWorkflowBandNfc ||
           workflow->identity.cascade_count != expected_cascade) {
            return false;
        }
    } else if(workflow->identity.atqa[0] || workflow->identity.atqa[1] ||
              workflow->identity.sak || workflow->identity.cascade_count) {
        return false;
    }
    if(workflow->band != DiagWorkflowBandNfc && workflow->identity.present) return false;
    if(workflow->source_path[0]) {
        if(workflow->band == DiagWorkflowBandNfc &&
           !diag_workflow_has_suffix(workflow->source_path, ".nfc")) {
            return false;
        }
        if(workflow->band == DiagWorkflowBandLf &&
           !diag_workflow_has_suffix(workflow->source_path, ".rfid")) {
            return false;
        }
        if(workflow->band == DiagWorkflowBandUnknown) return false;
    }
    return true;
}

void diag_workflow_init(DiagWorkflow* workflow, bool have_card) {
    if(!workflow) return;
    memset(workflow, 0, sizeof(*workflow));
    workflow->started = true;
    workflow->have_card = have_card;
    workflow->band = DiagWorkflowBandUnknown;
    workflow->pending_action = DiagWorkflowActionNone;
}

#ifdef DIAG_WORKFLOW_TESTING
bool diag_workflow_test_validate(const DiagWorkflow* workflow) {
    return diag_workflow_valid(workflow);
}

bool diag_workflow_test_parse_bool(const char* text, bool* value) {
    return diag_workflow_parse_bool(text, value);
}
#endif

#ifndef DIAG_WORKFLOW_HOST
static void diag_workflow_explain(FuriString* explanation, DiagFileStatus status) {
    if(explanation) furi_string_set(explanation, diag_file_status_string(status));
}

static bool diag_workflow_sync_temp(Storage* storage) {
    File* file = storage_file_alloc(storage);
    bool result = storage_file_open(
        file, DIAG_WORKFLOW_TEMP_PATH, FSAM_READ_WRITE, FSOM_OPEN_EXISTING);
    if(result) result = storage_file_sync(file);
    if(!storage_file_close(file)) result = false;
    storage_file_free(file);
    return result;
}

static bool diag_workflow_prepare_commit(Storage* storage) {
    if(!storage_file_exists(storage, DIAG_WORKFLOW_BACKUP_PATH)) return true;
    if(storage_file_exists(storage, DIAG_WORKFLOW_STATE_PATH)) {
        return storage_common_remove(storage, DIAG_WORKFLOW_BACKUP_PATH) == FSE_OK;
    }
    return storage_common_rename_safe(
               storage, DIAG_WORKFLOW_BACKUP_PATH, DIAG_WORKFLOW_STATE_PATH) == FSE_OK;
}

static bool diag_workflow_commit_temp(Storage* storage) {
    if(!diag_workflow_prepare_commit(storage)) return false;
    const bool had_state = storage_file_exists(storage, DIAG_WORKFLOW_STATE_PATH);
    if(had_state &&
       storage_common_rename_safe(
           storage, DIAG_WORKFLOW_STATE_PATH, DIAG_WORKFLOW_BACKUP_PATH) != FSE_OK) {
        return false;
    }
    if(storage_common_rename_safe(
           storage, DIAG_WORKFLOW_TEMP_PATH, DIAG_WORKFLOW_STATE_PATH) == FSE_OK) {
        if(had_state) storage_common_remove(storage, DIAG_WORKFLOW_BACKUP_PATH);
        return true;
    }
    if(had_state && !storage_file_exists(storage, DIAG_WORKFLOW_STATE_PATH)) {
        storage_common_rename_safe(
            storage, DIAG_WORKFLOW_BACKUP_PATH, DIAG_WORKFLOW_STATE_PATH);
    }
    return false;
}

DiagFileStatus diag_workflow_save(
    Storage* storage,
    const DiagWorkflow* workflow,
    FuriString* explanation) {
    if(!storage || !diag_workflow_valid(workflow)) return DiagFileStatusInvalidArgument;
    if(!storage_simply_mkdir(storage, DIAG_WORKFLOW_DIRECTORY)) {
        diag_workflow_explain(explanation, DiagFileStatusIo);
        return DiagFileStatusIo;
    }
    /* A synced temporary file replaces state only after the old state moves to backup.
       Load also accepts that backup after an interrupted replacement. */
    FlipperFormat* file = flipper_format_file_alloc(storage);
    const uint32_t band = (uint32_t)workflow->band;
    const uint32_t uid_size = (uint32_t)workflow->identity.uid_size;
    const uint32_t sak = workflow->identity.sak;
    const uint32_t cascade_count = workflow->identity.cascade_count;
    const uint32_t pending_action = workflow->pending_action;
    const char* source_path = workflow->source_path[0] ? workflow->source_path : "-";
    bool written = false;
    do {
        if(!flipper_format_file_open_always(file, DIAG_WORKFLOW_TEMP_PATH)) break;
        if(!flipper_format_write_header_cstr(
               file, DIAG_WORKFLOW_FILETYPE, DIAG_WORKFLOW_VERSION))
            break;
        if(!flipper_format_write_bool(file, "Started", &workflow->started, 1u)) break;
        if(!flipper_format_write_bool(file, "Have card", &workflow->have_card, 1u)) break;
        if(!flipper_format_write_uint32(file, "Band", &band, 1u)) break;
        if(!flipper_format_write_uint32(file, "UID length", &uid_size, 1u)) break;
        if(!flipper_format_write_hex(
               file, "UID", workflow->identity.uid, sizeof(workflow->identity.uid)))
            break;
        if(!flipper_format_write_hex(
               file, "ATQA", workflow->identity.atqa, sizeof(workflow->identity.atqa)))
            break;
        if(!flipper_format_write_uint32(file, "SAK", &sak, 1u)) break;
        if(!flipper_format_write_uint32(file, "Cascade count", &cascade_count, 1u)) break;
        if(!flipper_format_write_string_cstr(file, "Source path", source_path)) break;
        if(!flipper_format_write_uint32(file, "Pending action", &pending_action, 1u)) break;
        written = true;
    } while(false);
    if(!flipper_format_file_close(file)) written = false;
    flipper_format_free(file);

    DiagFileStatus status = DiagFileStatusIo;
    if(written && diag_workflow_sync_temp(storage) && diag_workflow_commit_temp(storage)) {
        status = DiagFileStatusOk;
    } else if(storage_file_exists(storage, DIAG_WORKFLOW_STATE_PATH)) {
        storage_simply_remove(storage, DIAG_WORKFLOW_TEMP_PATH);
    }
    diag_workflow_explain(explanation, status);
    return status;
}

static DiagFileStatus diag_workflow_load_path(
    Storage* storage,
    const char* path,
    DiagWorkflow* workflow) {
    File* size_file = storage_file_alloc(storage);
    if(!storage_file_open(size_file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_close(size_file);
        storage_file_free(size_file);
        return DiagFileStatusNotFound;
    }
    const uint64_t file_size = storage_file_size(size_file);
    bool size_closed = storage_file_close(size_file);
    storage_file_free(size_file);
    if(!size_closed) {
        return DiagFileStatusIo;
    }
    if(file_size == 0u || file_size > DIAG_WORKFLOW_MAX_FILE_SIZE) {
        DiagFileStatus status =
            file_size > DIAG_WORKFLOW_MAX_FILE_SIZE ? DiagFileStatusTooLarge :
                                                     DiagFileStatusInvalidFormat;
        return status;
    }

    DiagWorkflow loaded;
    memset(&loaded, 0, sizeof(loaded));
    FlipperFormat* file = flipper_format_file_alloc(storage);
    FuriString* filetype = furi_string_alloc();
    FuriString* source_path = furi_string_alloc();
    FuriString* bool_text = furi_string_alloc();
    uint32_t version = 0u;
    uint32_t band = 0u;
    uint32_t uid_size = 0u;
    uint32_t sak = 0u;
    uint32_t cascade_count = 0u;
    uint32_t pending_action = 0u;
    bool decoded = false;
    do {
        if(!flipper_format_file_open_existing(file, path)) break;
        flipper_format_set_strict_mode(file, true);
        if(!flipper_format_read_header(file, filetype, &version) ||
           furi_string_cmp_str(filetype, DIAG_WORKFLOW_FILETYPE) ||
           version != DIAG_WORKFLOW_VERSION)
            break;
        if(!flipper_format_read_string(file, "Started", bool_text) ||
           !diag_workflow_parse_bool(furi_string_get_cstr(bool_text), &loaded.started))
            break;
        if(!flipper_format_read_string(file, "Have card", bool_text) ||
           !diag_workflow_parse_bool(furi_string_get_cstr(bool_text), &loaded.have_card))
            break;
        if(!flipper_format_read_uint32(file, "Band", &band, 1u)) break;
        if(!flipper_format_read_uint32(file, "UID length", &uid_size, 1u)) break;
        if(!flipper_format_read_hex(
               file, "UID", loaded.identity.uid, sizeof(loaded.identity.uid)))
            break;
        if(!flipper_format_read_hex(
               file, "ATQA", loaded.identity.atqa, sizeof(loaded.identity.atqa)))
            break;
        if(!flipper_format_read_uint32(file, "SAK", &sak, 1u) || sak > UINT8_MAX) break;
        if(!flipper_format_read_uint32(file, "Cascade count", &cascade_count, 1u) ||
           cascade_count > UINT8_MAX)
            break;
        if(!flipper_format_read_string(file, "Source path", source_path)) break;
        if(!flipper_format_read_uint32(file, "Pending action", &pending_action, 1u)) break;
        const char* source = furi_string_get_cstr(source_path);
        if(furi_string_size(source_path) >= sizeof(loaded.source_path)) break;
        if(strcmp(source, "-"))
            memcpy(loaded.source_path, source, furi_string_size(source_path) + 1u);
        loaded.band = (DiagWorkflowBand)band;
        loaded.identity.uid_size = uid_size;
        loaded.identity.present = uid_size != 0u;
        loaded.identity.sak = (uint8_t)sak;
        loaded.identity.cascade_count = (uint8_t)cascade_count;
        loaded.pending_action = pending_action;
        decoded = diag_workflow_valid(&loaded);
    } while(false);
    if(!flipper_format_file_close(file)) decoded = false;
    furi_string_free(bool_text);
    furi_string_free(source_path);
    furi_string_free(filetype);
    flipper_format_free(file);

    const DiagFileStatus status = decoded ? DiagFileStatusOk : DiagFileStatusInvalidFormat;
    if(decoded) *workflow = loaded;
    return status;
}

DiagFileStatus diag_workflow_load(
    Storage* storage,
    DiagWorkflow* workflow,
    FuriString* explanation) {
    if(!storage || !workflow) return DiagFileStatusInvalidArgument;
    DiagWorkflow loaded;
    DiagFileStatus status =
        diag_workflow_load_path(storage, DIAG_WORKFLOW_STATE_PATH, &loaded);
    if(status != DiagFileStatusOk) {
        const DiagFileStatus backup_status =
            diag_workflow_load_path(storage, DIAG_WORKFLOW_BACKUP_PATH, &loaded);
        if(backup_status == DiagFileStatusOk) status = DiagFileStatusOk;
    }
    if(status == DiagFileStatusOk) *workflow = loaded;
    diag_workflow_explain(explanation, status);
    return status;
}
#endif
