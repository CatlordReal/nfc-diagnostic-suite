#include "diag_systems.h"

#include <stdio.h>
#include <string.h>

#if defined(DIAG_SYSTEMS_STORAGE_TESTING)
#include "tests/host/diag_systems_platform.h"
#elif !defined(DIAG_SYSTEMS_HOST)
#include <furi.h>
#include <storage/storage.h>
#endif

#define DIAG_SYSTEM_CURRENT_PATH DIAG_SYSTEM_UNGROUPED_DIRECTORY "/current_system.txt"
#define DIAG_SYSTEM_CURRENT_TEMP_PATH DIAG_SYSTEM_UNGROUPED_DIRECTORY "/current_system.tmp"
#define DIAG_SYSTEM_CURRENT_BACKUP_PATH DIAG_SYSTEM_UNGROUPED_DIRECTORY "/current_system.bak"
#define DIAG_SYSTEM_PROFILE_SUFFIX ".reader"
#define DIAG_SYSTEM_SESSION_SUFFIX ".nds"
#define DIAG_SYSTEM_DIRECTORY_ENTRY_LIMIT 384u

static size_t diag_system_bounded_strlen(const char* text, size_t capacity) {
    size_t size = 0u;
    if(!text) return capacity;
    while(size < capacity && text[size]) ++size;
    return size;
}

static void diag_system_copy(char* output, size_t capacity, const char* text) {
    if(!capacity) return;
    const size_t size = diag_system_bounded_strlen(text, capacity - 1u);
    memcpy(output, text, size);
    output[size] = '\0';
}

static bool diag_system_ascii_equal_ci(const char* left, const char* right) {
    while(*left && *right) {
        char a = *left++;
        char b = *right++;
        if(a >= 'a' && a <= 'z') a = (char)(a - ('a' - 'A'));
        if(b >= 'a' && b <= 'z') b = (char)(b - ('a' - 'A'));
        if(a != b) return false;
    }
    return *left == *right;
}

typedef enum {
    DiagSystemCreateInvalid,
    DiagSystemCreateExisting,
    DiagSystemCreateNew,
    DiagSystemCreateFull,
} DiagSystemCreateDecision;

static DiagSystemCreateDecision diag_system_create_decision(
    const DiagSystemList* list,
    const char* name,
    char canonical[DIAG_SYSTEM_NAME_CAPACITY]) {
    if(!list || !name || !name[0] || !diag_system_name_valid(name))
        return DiagSystemCreateInvalid;
    for(size_t index = 0u; index < list->count; ++index) {
        if(diag_system_ascii_equal_ci(list->names[index], name)) {
            if(canonical)
                diag_system_copy(canonical, DIAG_SYSTEM_NAME_CAPACITY, list->names[index]);
            return DiagSystemCreateExisting;
        }
    }
    if(list->truncated || list->count >= DIAG_SYSTEM_MAX_GROUPS)
        return DiagSystemCreateFull;
    if(canonical) diag_system_copy(canonical, DIAG_SYSTEM_NAME_CAPACITY, name);
    return DiagSystemCreateNew;
}

static bool diag_system_reserved_fat_name(const char* name) {
    char base[9] = {0};
    size_t size = 0u;
    while(name[size] && name[size] != '.' && size < sizeof(base) - 1u) {
        char c = name[size];
        base[size++] = c >= 'a' && c <= 'z' ? (char)(c - ('a' - 'A')) : c;
    }
    base[size] = '\0';
    if(diag_system_ascii_equal_ci(base, "CON") || diag_system_ascii_equal_ci(base, "PRN") ||
       diag_system_ascii_equal_ci(base, "AUX") || diag_system_ascii_equal_ci(base, "NUL")) {
        return true;
    }
    return size == 4u &&
           ((!memcmp(base, "COM", 3u) || !memcmp(base, "LPT", 3u)) &&
            base[3] >= '1' && base[3] <= '9');
}

static bool diag_system_component_valid(const char* name, size_t maximum, bool allow_empty) {
    const size_t size = diag_system_bounded_strlen(name, maximum + 1u);
    if(size > maximum || (!size && !allow_empty)) return false;
    if(!size) return true;
    if(name[0] == '.' || name[size - 1u] == '.' || name[size - 1u] == ' ') return false;
    for(size_t index = 0u; index < size; ++index) {
        const unsigned char c = (unsigned char)name[index];
        if(c < 0x20u || c > 0x7Eu || strchr("<>:\"/\\|?*", c)) return false;
    }
    return !diag_system_reserved_fat_name(name);
}

bool diag_system_name_valid(const char* name) {
    return diag_system_component_valid(name, DIAG_SYSTEM_NAME_CAPACITY - 1u, true);
}

bool diag_system_resolve_directory(
    const char* name,
    char output[DIAG_FILES_PATH_CAPACITY]) {
    if(!output || !diag_system_name_valid(name)) return false;
    const int length = name[0] ?
                           snprintf(
                               output,
                               DIAG_FILES_PATH_CAPACITY,
                               "%s/%s",
                               DIAG_SYSTEMS_ROOT_DIRECTORY,
                               name) :
                           snprintf(
                               output,
                               DIAG_FILES_PATH_CAPACITY,
                               "%s",
                               DIAG_SYSTEM_UNGROUPED_DIRECTORY);
    return length >= 0 && (size_t)length < DIAG_FILES_PATH_CAPACITY;
}

static bool diag_system_has_suffix(const char* text, const char* suffix) {
    const size_t text_size = strlen(text);
    const size_t suffix_size = strlen(suffix);
    return text_size > suffix_size && !strcmp(text + text_size - suffix_size, suffix);
}

static bool diag_system_profile_path(
    const char* directory,
    const char* session_path,
    char output[DIAG_FILES_PATH_CAPACITY]) {
    if(!directory || !*directory || !session_path || !output ||
       !diag_system_has_suffix(session_path, DIAG_SYSTEM_SESSION_SUFFIX)) {
        return false;
    }
    const size_t directory_size = strlen(directory);
    const bool trailing_slash = directory[directory_size - 1u] == '/';
    if(strncmp(session_path, directory, directory_size) ||
       (!trailing_slash && session_path[directory_size] != '/') ||
       (trailing_slash && session_path[directory_size] == '/')) {
        return false;
    }
    const char* filename = session_path + directory_size + (trailing_slash ? 0u : 1u);
    if(!*filename || strchr(filename, '/')) return false;
    const size_t filename_size = strlen(filename);
    const size_t suffix_size = sizeof(DIAG_SYSTEM_SESSION_SUFFIX) - 1u;
    if(filename_size <= suffix_size) return false;
    const size_t stem_size = filename_size - suffix_size;
    if(stem_size >= DIAG_SYSTEM_SESSION_STEM_CAPACITY) return false;
    char stem[DIAG_SYSTEM_SESSION_STEM_CAPACITY];
    memcpy(stem, filename, stem_size);
    stem[stem_size] = '\0';
    if(!diag_system_component_valid(stem, DIAG_SYSTEM_SESSION_STEM_CAPACITY - 1u, false))
        return false;
    const int length = snprintf(
        output,
        DIAG_FILES_PATH_CAPACITY,
        "%.*s%s",
        (int)(strlen(session_path) - suffix_size),
        session_path,
        DIAG_SYSTEM_PROFILE_SUFFIX);
    return length >= 0 && (size_t)length < DIAG_FILES_PATH_CAPACITY;
}

static bool diag_system_directory_valid(const char* directory) {
    if(!directory) return false;
    if(!strcmp(directory, DIAG_SYSTEM_UNGROUPED_DIRECTORY)) return true;
    const char prefix[] = DIAG_SYSTEMS_ROOT_DIRECTORY "/";
    if(strncmp(directory, prefix, sizeof(prefix) - 1u)) return false;
    const char* name = directory + sizeof(prefix) - 1u;
    return name[0] && !strchr(name, '/') && diag_system_name_valid(name);
}

static bool diag_system_current_decode(
    const uint8_t* data,
    size_t size,
    char name[DIAG_SYSTEM_NAME_CAPACITY]) {
    if(!data || !name || size < 1u || size > DIAG_SYSTEM_NAME_CAPACITY || data[size - 1u] != '\n')
        return false;
    const size_t name_size = size - 1u;
    for(size_t index = 0u; index < name_size; ++index) {
        if(!data[index] || data[index] == '\r' || data[index] == '\n') return false;
    }
    char decoded[DIAG_SYSTEM_NAME_CAPACITY];
    memcpy(decoded, data, name_size);
    decoded[name_size] = '\0';
    if(!diag_system_name_valid(decoded)) return false;
    memcpy(name, decoded, name_size + 1u);
    return true;
}

static void diag_system_consider_match(
    DiagSystemMatches* results,
    const char* group,
    const char* session_stem,
    const DiagReaderFingerprintMatch* comparison) {
    if(!results || !group || !session_stem || !comparison ||
       comparison->result != DiagReaderFingerprintSimilar) {
        return;
    }
    size_t position = 0u;
    while(position < results->count &&
          results->matches[position].score >= comparison->score) {
        ++position;
    }
    if(position >= DIAG_SYSTEM_MAX_MATCHES) return;
    size_t limit = results->count < DIAG_SYSTEM_MAX_MATCHES ? results->count :
                                                                DIAG_SYSTEM_MAX_MATCHES - 1u;
    while(limit > position) {
        results->matches[limit] = results->matches[limit - 1u];
        --limit;
    }
    DiagSystemMatch* match = &results->matches[position];
    memset(match, 0, sizeof(*match));
    diag_system_copy(match->group, sizeof(match->group), group);
    diag_system_copy(match->session_stem, sizeof(match->session_stem), session_stem);
    match->score = comparison->score;
    diag_system_copy(
        match->reason,
        sizeof(match->reason),
        comparison->reason ? comparison->reason : "Similar observed characteristics");
    if(results->count < DIAG_SYSTEM_MAX_MATCHES) ++results->count;
}

#ifdef DIAG_SYSTEMS_TESTING
bool diag_system_test_profile_path(
    const char* directory,
    const char* session_path,
    char output[DIAG_FILES_PATH_CAPACITY]) {
    return diag_system_directory_valid(directory) &&
           diag_system_profile_path(directory, session_path, output);
}

bool diag_system_test_current_decode(
    const uint8_t* data,
    size_t size,
    char name[DIAG_SYSTEM_NAME_CAPACITY]) {
    return diag_system_current_decode(data, size, name);
}

bool diag_system_test_profile_decode(
    const uint8_t* data,
    size_t size,
    DiagReaderFingerprint* fingerprint) {
    return diag_reader_fingerprint_decode(data, size, fingerprint);
}

void diag_system_test_consider_match(
    DiagSystemMatches* results,
    const char* group,
    const char* session_stem,
    const DiagReaderFingerprintMatch* comparison) {
    diag_system_consider_match(results, group, session_stem, comparison);
}

bool diag_system_test_create_allowed(
    const DiagSystemList* list,
    const char* name,
    bool* exists,
    char canonical[DIAG_SYSTEM_NAME_CAPACITY]) {
    const DiagSystemCreateDecision decision =
        diag_system_create_decision(list, name, canonical);
    if(exists) *exists = decision == DiagSystemCreateExisting;
    return decision == DiagSystemCreateExisting || decision == DiagSystemCreateNew;
}
#endif

#ifndef DIAG_SYSTEMS_HOST
static void diag_system_explain(
    FuriString* explanation,
    const char* operation,
    DiagFileStatus status,
    FS_Error error,
    const char* path) {
    if(!explanation) return;
    if(error == FSE_OK) {
        furi_string_printf(explanation, "%s: %s", operation, diag_file_status_string(status));
    } else {
        furi_string_printf(
            explanation,
            "%s failed: %s (FS_Error %u)\n%s",
            operation,
            storage_error_get_desc(error),
            (unsigned)error,
            path ? path : "Path unavailable");
    }
}

static void diag_system_sort(DiagSystemList* list) {
    for(size_t index = 1u; index < list->count; ++index) {
        char value[DIAG_SYSTEM_NAME_CAPACITY];
        memcpy(value, list->names[index], sizeof(value));
        size_t position = index;
        while(position && strcmp(list->names[position - 1u], value) > 0) {
            memcpy(list->names[position], list->names[position - 1u], sizeof(value));
            --position;
        }
        memcpy(list->names[position], value, sizeof(value));
    }
}

DiagFileStatus diag_system_list(
    Storage* storage,
    DiagSystemList* list,
    FuriString* explanation) {
    if(!storage || !list) return DiagFileStatusInvalidArgument;
    memset(list, 0, sizeof(*list));
    DiagFileStatus status =
        diag_files_ensure_directory(storage, DIAG_SYSTEMS_ROOT_DIRECTORY, explanation);
    if(status != DiagFileStatusOk) return status;
    File* directory = storage_file_alloc(storage);
    if(!storage_dir_open(directory, DIAG_SYSTEMS_ROOT_DIRECTORY)) {
        const FS_Error error = storage_file_get_error(directory);
        storage_dir_close(directory);
        storage_file_free(directory);
        diag_system_explain(
            explanation, "List systems", DiagFileStatusIo, error, DIAG_SYSTEMS_ROOT_DIRECTORY);
        return DiagFileStatusIo;
    }
    size_t entries = 0u;
    char name[96];
    FileInfo info;
    while(entries++ < DIAG_SYSTEM_DIRECTORY_ENTRY_LIMIT &&
          storage_dir_read(directory, &info, name, sizeof(name))) {
        if(!file_info_is_dir(&info) || !diag_system_name_valid(name) || !name[0]) continue;
        if(list->count < DIAG_SYSTEM_MAX_GROUPS) {
            diag_system_copy(
                list->names[list->count++], DIAG_SYSTEM_NAME_CAPACITY, name);
        } else {
            list->truncated = true;
        }
    }
    FS_Error read_error = storage_file_get_error(directory);
    if(entries > DIAG_SYSTEM_DIRECTORY_ENTRY_LIMIT) list->truncated = true;
    const bool closed = storage_dir_close(directory);
    const FS_Error close_error = closed ? FSE_OK : storage_file_get_error(directory);
    storage_file_free(directory);
    if(read_error != FSE_NOT_EXIST && read_error != FSE_OK) {
        diag_system_explain(
            explanation, "List systems", DiagFileStatusIo, read_error, DIAG_SYSTEMS_ROOT_DIRECTORY);
        return DiagFileStatusIo;
    }
    if(!closed) {
        diag_system_explain(
            explanation, "Close systems", DiagFileStatusIo, close_error, DIAG_SYSTEMS_ROOT_DIRECTORY);
        return DiagFileStatusIo;
    }
    diag_system_sort(list);
    diag_system_explain(explanation, "List systems", DiagFileStatusOk, FSE_OK, NULL);
    return DiagFileStatusOk;
}

DiagFileStatus diag_system_create(
    Storage* storage,
    const char* name,
    FuriString* explanation) {
    char directory[DIAG_FILES_PATH_CAPACITY];
    if(!storage || !name || !name[0] || !diag_system_resolve_directory(name, directory))
        return DiagFileStatusInvalidArgument;
    DiagSystemList systems;
    DiagFileStatus status = diag_system_list(storage, &systems, explanation);
    if(status != DiagFileStatusOk) return status;
    char canonical[DIAG_SYSTEM_NAME_CAPACITY];
    const DiagSystemCreateDecision decision =
        diag_system_create_decision(&systems, name, canonical);
    if(decision == DiagSystemCreateExisting) {
        diag_system_explain(explanation, "Create system", DiagFileStatusOk, FSE_OK, NULL);
        return DiagFileStatusOk;
    }
    if(decision == DiagSystemCreateFull) {
        if(explanation)
            furi_string_printf(
                explanation,
                "Create system: %s\nMaximum %u systems",
                diag_file_status_string(DiagFileStatusTooLarge),
                (unsigned)DIAG_SYSTEM_MAX_GROUPS);
        return DiagFileStatusTooLarge;
    }
    if(decision != DiagSystemCreateNew) return DiagFileStatusInvalidArgument;
    return diag_files_ensure_directory(storage, directory, explanation);
}

static DiagFileStatus diag_system_current_read(
    Storage* storage,
    const char* path,
    char name[DIAG_SYSTEM_NAME_CAPACITY],
    FS_Error* error_out) {
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        *error_out = storage_file_get_error(file);
        storage_file_close(file);
        storage_file_free(file);
        return *error_out == FSE_NOT_EXIST ? DiagFileStatusNotFound : DiagFileStatusIo;
    }
    const uint64_t size = storage_file_size(file);
    uint8_t data[DIAG_SYSTEM_NAME_CAPACITY];
    DiagFileStatus status = size >= 1u && size <= sizeof(data) ? DiagFileStatusOk :
                                                                  DiagFileStatusInvalidFormat;
    if(status == DiagFileStatusOk && storage_file_read(file, data, (size_t)size) != size) {
        *error_out = storage_file_get_error(file);
        status = DiagFileStatusIo;
    }
    const bool closed = storage_file_close(file);
    if(!closed && status == DiagFileStatusOk) {
        *error_out = storage_file_get_error(file);
        status = DiagFileStatusIo;
    }
    storage_file_free(file);
    if(status == DiagFileStatusOk && !diag_system_current_decode(data, (size_t)size, name))
        status = DiagFileStatusInvalidFormat;
    return status;
}

DiagFileStatus diag_system_current_load(
    Storage* storage,
    char name[DIAG_SYSTEM_NAME_CAPACITY],
    FuriString* explanation) {
    if(!storage || !name) return DiagFileStatusInvalidArgument;
    char loaded[DIAG_SYSTEM_NAME_CAPACITY];
    FS_Error state_error = FSE_OK;
    DiagFileStatus status =
        diag_system_current_read(storage, DIAG_SYSTEM_CURRENT_PATH, loaded, &state_error);
    if(status != DiagFileStatusOk) {
        const DiagFileStatus state_status = status;
        FS_Error backup_error = FSE_OK;
        const DiagFileStatus backup_status = diag_system_current_read(
            storage, DIAG_SYSTEM_CURRENT_BACKUP_PATH, loaded, &backup_error);
        if(backup_status != DiagFileStatusOk) {
            status = state_status != DiagFileStatusNotFound ? state_status : backup_status;
            const FS_Error error = state_status != DiagFileStatusNotFound ? state_error : backup_error;
            diag_system_explain(
                explanation, "Load current system", status, error,
                state_status != DiagFileStatusNotFound ? DIAG_SYSTEM_CURRENT_PATH : DIAG_SYSTEM_CURRENT_BACKUP_PATH);
            return status;
        }
        status = backup_status;
    }
    memcpy(name, loaded, sizeof(loaded));
    diag_system_explain(explanation, "Load current system", DiagFileStatusOk, FSE_OK, NULL);
    return DiagFileStatusOk;
}

typedef struct {
    FS_Error error;
    FS_Error rollback_error;
    const char* operation;
    const char* path;
} DiagSystemCommitResult;

static DiagSystemCommitResult diag_system_commit_current(Storage* storage) {
    DiagSystemCommitResult result = {.operation = "Publish current system", .path = DIAG_SYSTEM_CURRENT_TEMP_PATH};
    if(storage_file_exists(storage, DIAG_SYSTEM_CURRENT_BACKUP_PATH)) {
        result.path = DIAG_SYSTEM_CURRENT_BACKUP_PATH;
        if(storage_file_exists(storage, DIAG_SYSTEM_CURRENT_PATH)) {
            result.operation = "Remove old system backup";
            result.error = storage_common_remove(storage, DIAG_SYSTEM_CURRENT_BACKUP_PATH);
        } else {
            result.operation = "Restore system backup";
            result.error = storage_common_rename_safe(storage, DIAG_SYSTEM_CURRENT_BACKUP_PATH, DIAG_SYSTEM_CURRENT_PATH);
        }
        if(result.error != FSE_OK) return result;
    }
    const bool had_state = storage_file_exists(storage, DIAG_SYSTEM_CURRENT_PATH);
    if(had_state) {
        result.operation = "Back up current system";
        result.path = DIAG_SYSTEM_CURRENT_PATH;
        result.error = storage_common_rename_safe(storage, DIAG_SYSTEM_CURRENT_PATH, DIAG_SYSTEM_CURRENT_BACKUP_PATH);
        if(result.error != FSE_OK) return result;
    }
    result.operation = "Publish current system";
    result.path = DIAG_SYSTEM_CURRENT_TEMP_PATH;
    result.error = storage_common_rename_safe(storage, DIAG_SYSTEM_CURRENT_TEMP_PATH, DIAG_SYSTEM_CURRENT_PATH);
    if(result.error == FSE_OK) {
        /* The new state is durable. A leftover backup is safe to retain. */
        if(had_state) storage_common_remove(storage, DIAG_SYSTEM_CURRENT_BACKUP_PATH);
    } else if(had_state && !storage_file_exists(storage, DIAG_SYSTEM_CURRENT_PATH)) {
        result.rollback_error = storage_common_rename_safe(storage, DIAG_SYSTEM_CURRENT_BACKUP_PATH, DIAG_SYSTEM_CURRENT_PATH);
    }
    return result;
}

DiagFileStatus diag_system_current_save(
    Storage* storage,
    const char* name,
    FuriString* explanation) {
    if(!storage || !diag_system_name_valid(name)) return DiagFileStatusInvalidArgument;
    DiagFileStatus status =
        diag_files_ensure_directory(storage, DIAG_SYSTEM_UNGROUPED_DIRECTORY, explanation);
    if(status != DiagFileStatusOk) return status;
    uint8_t data[DIAG_SYSTEM_NAME_CAPACITY];
    const size_t name_size = strlen(name);
    memcpy(data, name, name_size);
    data[name_size] = '\n';
    File* file = storage_file_alloc(storage);
    FS_Error error = FSE_OK;
    if(!storage_file_open(file, DIAG_SYSTEM_CURRENT_TEMP_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        error = storage_file_get_error(file);
        status = DiagFileStatusIo;
    } else if(storage_file_write(file, data, name_size + 1u) != name_size + 1u) {
        error = storage_file_get_error(file);
        status = DiagFileStatusIo;
    } else if(!storage_file_sync(file)) {
        error = storage_file_get_error(file);
        status = DiagFileStatusIo;
    }
    const bool closed = storage_file_close(file);
    if(!closed && status == DiagFileStatusOk) {
        error = storage_file_get_error(file);
        status = DiagFileStatusIo;
    }
    storage_file_free(file);
    if(status == DiagFileStatusOk) {
        DiagSystemCommitResult result = diag_system_commit_current(storage);
        error = result.error;
        if(error != FSE_OK) {
            status = DiagFileStatusIo;
            diag_system_explain(explanation, result.operation, status, error, result.path);
            if(explanation && result.rollback_error != FSE_OK)
                furi_string_cat_printf(explanation, "\nRestore backup: FS_Error %u\n%s", (unsigned)result.rollback_error, DIAG_SYSTEM_CURRENT_BACKUP_PATH);
        }
    } else diag_system_explain(explanation, "Write current system", status, error, DIAG_SYSTEM_CURRENT_TEMP_PATH);
    if(status == DiagFileStatusOk) diag_system_explain(explanation, "Save current system", status, FSE_OK, NULL);
    else if(explanation && storage_file_exists(storage, DIAG_SYSTEM_CURRENT_TEMP_PATH))
        furi_string_cat_printf(explanation, "\nTemporary retained: %s", DIAG_SYSTEM_CURRENT_TEMP_PATH);
    return status;
}

typedef struct {
    FS_Error error;
    char path[DIAG_FILES_PATH_CAPACITY];
} DiagSystemStorageFailure;

static void diag_system_failure_set(
    DiagSystemStorageFailure* failure,
    FS_Error error,
    const char* path) {
    if(!failure || failure->error != FSE_OK) return;
    failure->error = error == FSE_OK ? FSE_INTERNAL : error;
    diag_system_copy(failure->path, sizeof(failure->path), path);
}

static DiagFileStatus diag_system_read_profile(
    Storage* storage,
    const char* path,
    DiagReaderFingerprint* fingerprint,
    DiagSystemStorageFailure* failure) {
    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        const FS_Error error = storage_file_get_error(file);
        storage_file_close(file);
        storage_file_free(file);
        diag_system_failure_set(failure, error, path);
        return DiagFileStatusIo;
    }
    uint8_t data[DIAG_READER_FINGERPRINT_ENCODED_SIZE];
    DiagFileStatus status =
        storage_file_size(file) == sizeof(data) ? DiagFileStatusOk : DiagFileStatusInvalidFormat;
    if(status == DiagFileStatusOk && storage_file_read(file, data, sizeof(data)) != sizeof(data)) {
        diag_system_failure_set(failure, storage_file_get_error(file), path);
        status = DiagFileStatusIo;
    }
    if(!storage_file_close(file) && status == DiagFileStatusOk) {
        diag_system_failure_set(failure, storage_file_get_error(file), path);
        status = DiagFileStatusIo;
    }
    storage_file_free(file);
    if(status == DiagFileStatusOk &&
       !diag_reader_fingerprint_decode(data, sizeof(data), fingerprint)) {
        status = DiagFileStatusInvalidFormat;
    }
    return status;
}

DiagFileStatus diag_system_save_reader_profile(
    Storage* storage,
    const char* directory,
    const char* session_path,
    const DiagReaderFingerprint* fingerprint,
    char output_path[DIAG_FILES_PATH_CAPACITY],
    FuriString* explanation) {
    if(output_path) output_path[0] = '\0';
    if(!storage || !fingerprint || !output_path || !diag_system_directory_valid(directory) ||
       !diag_system_profile_path(directory, session_path, output_path)) {
        return DiagFileStatusInvalidArgument;
    }
    FileInfo session_info;
    const FS_Error session_error = storage_common_stat(storage, session_path, &session_info);
    if(session_error != FSE_OK) {
        const DiagFileStatus status =
            session_error == FSE_NOT_EXIST ? DiagFileStatusNotFound : DiagFileStatusIo;
        diag_system_explain(
            explanation, "Check saved session", status, session_error, session_path);
        return status;
    }
    if(file_info_is_dir(&session_info)) return DiagFileStatusInvalidArgument;
    uint8_t data[DIAG_READER_FINGERPRINT_ENCODED_SIZE];
    if(diag_reader_fingerprint_encode(fingerprint, data, sizeof(data)) != sizeof(data))
        return DiagFileStatusInvalidFormat;
    if(storage_file_exists(storage, output_path)) {
        diag_system_explain(explanation, "Save reader profile", DiagFileStatusExists, FSE_OK, output_path);
        return DiagFileStatusExists;
    }
    char temporary[DIAG_FILES_PATH_CAPACITY + 5u];
    const int temporary_size = snprintf(temporary, sizeof(temporary), "%s.tmp", output_path);
    if(temporary_size < 0 || (size_t)temporary_size >= sizeof(temporary))
        return DiagFileStatusInvalidArgument;
    if(storage_file_exists(storage, temporary)) storage_simply_remove(storage, temporary);
    File* file = storage_file_alloc(storage);
    DiagFileStatus status = DiagFileStatusOk;
    FS_Error error = FSE_OK;
    if(!storage_file_open(file, temporary, FSAM_WRITE, FSOM_CREATE_NEW)) {
        error = storage_file_get_error(file);
        status = error == FSE_EXIST ? DiagFileStatusExists : DiagFileStatusIo;
    } else if(storage_file_write(file, data, sizeof(data)) != sizeof(data)) {
        error = storage_file_get_error(file);
        status = DiagFileStatusIo;
    } else if(!storage_file_sync(file)) {
        error = storage_file_get_error(file);
        status = DiagFileStatusIo;
    }
    const bool closed = storage_file_close(file);
    if(!closed && status == DiagFileStatusOk) {
        error = storage_file_get_error(file);
        status = DiagFileStatusIo;
    }
    storage_file_free(file);
    if(status == DiagFileStatusOk) {
        error = storage_common_rename_safe(storage, temporary, output_path);
        if(error != FSE_OK)
            status = error == FSE_EXIST ? DiagFileStatusExists : DiagFileStatusIo;
    }
    if(status != DiagFileStatusOk) storage_simply_remove(storage, temporary);
    diag_system_explain(explanation, "Save reader profile", status, error, output_path);
    return status;
}

static bool diag_system_reader_filename(const char* filename, char stem[DIAG_SYSTEM_SESSION_STEM_CAPACITY]) {
    if(!diag_system_has_suffix(filename, DIAG_SYSTEM_PROFILE_SUFFIX)) return false;
    const size_t suffix_size = sizeof(DIAG_SYSTEM_PROFILE_SUFFIX) - 1u;
    const size_t stem_size = strlen(filename) - suffix_size;
    if(!stem_size || stem_size >= DIAG_SYSTEM_SESSION_STEM_CAPACITY) return false;
    memcpy(stem, filename, stem_size);
    stem[stem_size] = '\0';
    return diag_system_component_valid(stem, DIAG_SYSTEM_SESSION_STEM_CAPACITY - 1u, false);
}

static DiagFileStatus diag_system_scan_directory(
    Storage* storage,
    const char* directory_path,
    const char* group,
    const DiagReaderFingerprint* current,
    DiagSystemMatches* results,
    size_t* entries_seen,
    DiagSystemStorageFailure* failure) {
    File* directory = storage_file_alloc(storage);
    if(!storage_dir_open(directory, directory_path)) {
        const FS_Error error = storage_file_get_error(directory);
        storage_dir_close(directory);
        storage_file_free(directory);
        diag_system_failure_set(failure, error, directory_path);
        return DiagFileStatusIo;
    }
    FileInfo info;
    char filename[96];
    while(*entries_seen < DIAG_SYSTEM_DIRECTORY_ENTRY_LIMIT &&
          results->files_seen < DIAG_SYSTEM_MAX_PROFILES &&
          storage_dir_read(directory, &info, filename, sizeof(filename))) {
        ++*entries_seen;
        if(file_info_is_dir(&info)) continue;
        char stem[DIAG_SYSTEM_SESSION_STEM_CAPACITY];
        if(!diag_system_reader_filename(filename, stem)) continue;
        ++results->files_seen;
        char path[DIAG_FILES_PATH_CAPACITY];
        const int length = snprintf(path, sizeof(path), "%s/%s", directory_path, filename);
        if(length < 0 || (size_t)length >= sizeof(path)) {
            ++results->invalid_files;
            continue;
        }
        char session_path[DIAG_FILES_PATH_CAPACITY];
        const int session_length = snprintf(
            session_path, sizeof(session_path), "%s/%s%s", directory_path, stem, DIAG_SYSTEM_SESSION_SUFFIX);
        if(session_length < 0 || (size_t)session_length >= sizeof(session_path)) {
            ++results->invalid_files;
            continue;
        }
        FileInfo session_info;
        const FS_Error session_error = storage_common_stat(storage, session_path, &session_info);
        if(session_error == FSE_NOT_EXIST ||
           (session_error == FSE_OK && file_info_is_dir(&session_info))) {
            ++results->invalid_files;
            continue;
        }
        if(session_error != FSE_OK) {
            diag_system_failure_set(failure, session_error, session_path);
            storage_dir_close(directory);
            storage_file_free(directory);
            return DiagFileStatusIo;
        }
        DiagReaderFingerprint prior;
        const DiagFileStatus profile_status =
            diag_system_read_profile(storage, path, &prior, failure);
        if(profile_status == DiagFileStatusIo) {
            storage_dir_close(directory);
            storage_file_free(directory);
            return profile_status;
        }
        if(profile_status != DiagFileStatusOk) {
            ++results->invalid_files;
            continue;
        }
        ++results->files_decoded;
        const DiagReaderFingerprintMatch comparison =
            diag_reader_fingerprint_compare(current, &prior);
        if(comparison.result == DiagReaderFingerprintSimilar) {
            diag_system_consider_match(results, group, stem, &comparison);
        } else if(comparison.result == DiagReaderFingerprintInsufficient) {
            ++results->insufficient_files;
        } else if(comparison.result == DiagReaderFingerprintNotComparable) {
            ++results->not_comparable_files;
        } else if(comparison.result == DiagReaderFingerprintInvalid) {
            ++results->invalid_files;
        }
    }
    if(*entries_seen >= DIAG_SYSTEM_DIRECTORY_ENTRY_LIMIT ||
       results->files_seen >= DIAG_SYSTEM_MAX_PROFILES) {
        results->truncated = true;
    }
    const FS_Error read_error = storage_file_get_error(directory);
    const bool closed = storage_dir_close(directory);
    const FS_Error close_error = closed ? FSE_OK : storage_file_get_error(directory);
    storage_file_free(directory);
    if(read_error != FSE_NOT_EXIST && read_error != FSE_OK) {
        diag_system_failure_set(failure, read_error, directory_path);
        return DiagFileStatusIo;
    }
    if(!closed) {
        diag_system_failure_set(failure, close_error, directory_path);
        return DiagFileStatusIo;
    }
    return DiagFileStatusOk;
}

DiagFileStatus diag_system_find_similar(
    Storage* storage,
    const DiagReaderFingerprint* current,
    DiagSystemMatches* results,
    FuriString* explanation) {
    if(!storage || !current || !results) return DiagFileStatusInvalidArgument;
    uint8_t validation[DIAG_READER_FINGERPRINT_ENCODED_SIZE];
    if(diag_reader_fingerprint_encode(current, validation, sizeof(validation)) != sizeof(validation))
        return DiagFileStatusInvalidFormat;
    memset(results, 0, sizeof(*results));
    DiagSystemList systems;
    DiagFileStatus status = diag_system_list(storage, &systems, explanation);
    if(status != DiagFileStatusOk) return status;
    size_t entries_seen = 0u;
    DiagSystemStorageFailure failure = {0};
    status = diag_system_scan_directory(
        storage,
        DIAG_SYSTEM_UNGROUPED_DIRECTORY,
        "",
        current,
        results,
        &entries_seen,
        &failure);
    for(size_t index = 0u; status == DiagFileStatusOk && index < systems.count &&
                           !results->truncated;
        ++index) {
        char directory[DIAG_FILES_PATH_CAPACITY];
        if(!diag_system_resolve_directory(systems.names[index], directory)) {
            status = DiagFileStatusInvalidFormat;
            break;
        }
        status = diag_system_scan_directory(
            storage,
            directory,
            systems.names[index],
            current,
            results,
            &entries_seen,
            &failure);
    }
    if(systems.truncated) results->truncated = true;
    diag_system_explain(
        explanation,
        "Compare reader profiles",
        status,
        failure.error,
        failure.path[0] ? failure.path : NULL);
    return status;
}
#else
DiagFileStatus diag_system_list(Storage* storage, DiagSystemList* list, FuriString* explanation) {
    (void)storage;
    (void)list;
    (void)explanation;
    return DiagFileStatusUnsupported;
}
DiagFileStatus diag_system_create(Storage* storage, const char* name, FuriString* explanation) {
    (void)storage;
    (void)name;
    (void)explanation;
    return DiagFileStatusUnsupported;
}
DiagFileStatus diag_system_current_load(Storage* storage, char name[DIAG_SYSTEM_NAME_CAPACITY], FuriString* explanation) {
    (void)storage;
    (void)name;
    (void)explanation;
    return DiagFileStatusUnsupported;
}
DiagFileStatus diag_system_current_save(Storage* storage, const char* name, FuriString* explanation) {
    (void)storage;
    (void)name;
    (void)explanation;
    return DiagFileStatusUnsupported;
}
DiagFileStatus diag_system_save_reader_profile(Storage* storage, const char* directory, const char* session_path, const DiagReaderFingerprint* fingerprint, char output_path[DIAG_FILES_PATH_CAPACITY], FuriString* explanation) {
    (void)storage;
    (void)directory;
    (void)session_path;
    (void)fingerprint;
    (void)output_path;
    (void)explanation;
    return DiagFileStatusUnsupported;
}
DiagFileStatus diag_system_find_similar(Storage* storage, const DiagReaderFingerprint* current, DiagSystemMatches* results, FuriString* explanation) {
    (void)storage;
    (void)current;
    (void)results;
    (void)explanation;
    return DiagFileStatusUnsupported;
}
#endif
