#include "../diag_tools_loader.h"
#include "host/diag_tools_loader_platform.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Storage {
    unsigned unused;
};

struct FuriString {
    char text[256];
};

struct ElfApiInterface {
    unsigned unused;
};

struct PluginManager {
    unsigned unused;
};

static struct ElfApiInterface test_interface;
const ElfApiInterface* const firmware_api_interface = &test_interface;

static FS_Error test_stat_error;
static FileInfo test_file_info;
static size_t test_free_heap;
static size_t test_max_block;
static size_t test_ready_free_heap;
static size_t test_ready_max_block;
static PluginManagerError test_load_error;
static uint32_t test_plugin_count;
static const DiagToolsApi* test_plugin_api;
static unsigned test_manager_allocs;
static unsigned test_manager_frees;

FS_Error storage_common_stat(Storage* storage, const char* path, FileInfo* info) {
    assert(storage);
    assert(!strcmp(path, "/assets/plugins/nfc_diag_tools.fal"));
    if(test_stat_error == FSE_OK) *info = test_file_info;
    return test_stat_error;
}

const char* storage_error_get_desc(FS_Error error) {
    return error == FSE_NOT_EXIST ? "not found" : "test error";
}

bool file_info_is_dir(const FileInfo* info) {
    return (info->flags & 1u) != 0u;
}

size_t memmgr_get_free_heap(void) {
    return test_manager_allocs ? test_ready_free_heap : test_free_heap;
}

size_t memmgr_heap_get_max_free_block(void) {
    return test_manager_allocs ? test_ready_max_block : test_max_block;
}

void furi_string_reset(FuriString* string) {
    string->text[0] = '\0';
}

void furi_string_set(FuriString* string, const char* text) {
    snprintf(string->text, sizeof(string->text), "%s", text);
}

void furi_string_printf(FuriString* string, const char* format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(string->text, sizeof(string->text), format, args);
    va_end(args);
}

PluginManager* plugin_manager_alloc(
    const char* application_id,
    uint32_t api_version,
    const ElfApiInterface* api_interface) {
    assert(!strcmp(application_id, DIAG_TOOLS_PLUGIN_APP_ID));
    assert(api_version == DIAG_TOOLS_PLUGIN_API_VERSION);
    assert(api_interface == firmware_api_interface);
    ++test_manager_allocs;
    return malloc(sizeof(PluginManager));
}

void plugin_manager_free(PluginManager* manager) {
    assert(manager);
    ++test_manager_frees;
    free(manager);
}

PluginManagerError plugin_manager_load_single(PluginManager* manager, const char* path) {
    assert(manager);
    assert(!strcmp(path, "/assets/plugins/nfc_diag_tools.fal"));
    return test_load_error;
}

uint32_t plugin_manager_get_count(PluginManager* manager) {
    assert(manager);
    return test_plugin_count;
}

const void* plugin_manager_get_ep(PluginManager* manager, uint32_t index) {
    assert(manager);
    assert(index == 0u);
    return test_plugin_api;
}

static bool dummy_recommend(
    const DiagModel* model,
    const DiagReaderStats* reader,
    const DiagLfStats* fields,
    DiagInsightRecommendation* recommendation) {
    (void)model;
    (void)reader;
    (void)fields;
    (void)recommendation;
    return true;
}

static bool dummy_from_reader(
    const DiagReaderStats* stats,
    const DiagIsoAIdentity* stimulus,
    DiagReaderFingerprint* fingerprint) {
    (void)stats;
    (void)stimulus;
    (void)fingerprint;
    return true;
}

static bool dummy_from_fields(
    const DiagLfStats* stats,
    DiagReaderFingerprint* fingerprint) {
    (void)stats;
    (void)fingerprint;
    return true;
}

static bool dummy_resolve(const char* name, char output[DIAG_FILES_PATH_CAPACITY]) {
    (void)name;
    (void)output;
    return true;
}

static DiagFileStatus dummy_current_load(
    Storage* storage,
    char name[DIAG_SYSTEM_NAME_CAPACITY],
    FuriString* explanation) {
    (void)storage;
    (void)name;
    (void)explanation;
    return DiagFileStatusOk;
}

static DiagFileStatus dummy_save(
    Storage* storage,
    const char* directory,
    const char* session_path,
    const DiagReaderFingerprint* fingerprint,
    char output_path[DIAG_FILES_PATH_CAPACITY],
    FuriString* explanation) {
    (void)storage;
    (void)directory;
    (void)session_path;
    (void)fingerprint;
    (void)output_path;
    (void)explanation;
    return DiagFileStatusOk;
}

static DiagFileStatus dummy_find(
    Storage* storage,
    const DiagReaderFingerprint* current,
    DiagSystemMatches* results,
    FuriString* explanation) {
    (void)storage;
    (void)current;
    (void)results;
    (void)explanation;
    return DiagFileStatusOk;
}

static bool dummy_choose(
    Storage* storage,
    Gui* gui,
    char name[DIAG_SYSTEM_NAME_CAPACITY],
    FuriString* explanation) {
    (void)storage;
    (void)gui;
    (void)name;
    (void)explanation;
    return true;
}

static const DiagToolsApi valid_api = {
    .recommend = dummy_recommend,
    .from_reader = dummy_from_reader,
    .from_fields = dummy_from_fields,
    .resolve_directory = dummy_resolve,
    .current_load = dummy_current_load,
    .save_reader_profile = dummy_save,
    .find_similar = dummy_find,
    .choose = dummy_choose,
};

static void reset_test(void) {
    test_stat_error = FSE_OK;
    test_file_info = (FileInfo){.size = 24068u};
    test_free_heap = 40u * 1024u;
    test_max_block = 16u * 1024u;
    test_ready_free_heap = 16u * 1024u;
    test_ready_max_block = 8u * 1024u;
    test_load_error = PluginManagerErrorNone;
    test_plugin_count = 1u;
    test_plugin_api = &valid_api;
    test_manager_allocs = 0u;
    test_manager_frees = 0u;
}

static void expect_open_failure(Storage* storage, FuriString* explanation) {
    assert(!diag_tools_open(storage, explanation));
    assert(test_manager_allocs == test_manager_frees);
}

static void test_preflight_rejection(void) {
    Storage storage = {0};
    FuriString explanation;
    reset_test();
    test_stat_error = FSE_NOT_EXIST;
    expect_open_failure(&storage, &explanation);
    assert(strstr(explanation.text, "FS_Error 3"));
    assert(test_manager_allocs == 0u);

    reset_test();
    test_file_info.flags = 1u;
    expect_open_failure(&storage, &explanation);
    assert(test_manager_allocs == 0u);

    reset_test();
    test_file_info.size = 0u;
    expect_open_failure(&storage, &explanation);
    assert(test_manager_allocs == 0u);

    reset_test();
    test_file_info.size = 128u * 1024u + 1u;
    expect_open_failure(&storage, &explanation);
    assert(test_manager_allocs == 0u);

    reset_test();
    test_free_heap = 32767u;
    expect_open_failure(&storage, &explanation);
    assert(strstr(explanation.text, "Free 32767"));
    assert(test_manager_allocs == 0u);

    reset_test();
    test_max_block = 12287u;
    expect_open_failure(&storage, &explanation);
    assert(test_manager_allocs == 0u);
}

static void test_loader_failures_release_manager(void) {
    Storage storage = {0};
    FuriString explanation;
    const PluginManagerError errors[] = {
        PluginManagerErrorLoaderError,
        PluginManagerErrorApplicationIdMismatch,
        PluginManagerErrorAPIVersionMismatch,
    };
    for(size_t index = 0u; index < sizeof(errors) / sizeof(errors[0]); ++index) {
        reset_test();
        test_load_error = errors[index];
        expect_open_failure(&storage, &explanation);
        assert(explanation.text[0]);
        assert(test_manager_frees == 1u);
    }

    reset_test();
    test_plugin_count = 0u;
    expect_open_failure(&storage, &explanation);
    assert(test_manager_frees == 1u);

    reset_test();
    DiagToolsApi incomplete = valid_api;
    incomplete.choose = NULL;
    test_plugin_api = &incomplete;
    expect_open_failure(&storage, &explanation);
    assert(strstr(explanation.text, "incomplete"));
    assert(test_manager_frees == 1u);

    reset_test();
    test_ready_free_heap = 12287u;
    expect_open_failure(&storage, &explanation);
    assert(strstr(explanation.text, "working RAM"));
    assert(test_manager_frees == 1u);

    reset_test();
    test_ready_max_block = 4095u;
    expect_open_failure(&storage, &explanation);
    assert(strstr(explanation.text, "working RAM"));
    assert(test_manager_frees == 1u);
}

static void test_success_lifecycle(void) {
    Storage storage = {0};
    FuriString explanation;
    reset_test();
    assert(diag_tools_api(NULL) == NULL);
    diag_tools_close(NULL);
    DiagTools* tools = diag_tools_open(&storage, &explanation);
    assert(tools);
    assert(diag_tools_api(tools) == &valid_api);
    assert(test_manager_allocs == 1u && test_manager_frees == 0u);
    diag_tools_close(tools);
    assert(test_manager_frees == 1u);
}

int main(void) {
    test_preflight_rejection();
    test_loader_failures_release_manager();
    test_success_lifecycle();
    puts("diag_tools_loader tests passed");
    return 0;
}
