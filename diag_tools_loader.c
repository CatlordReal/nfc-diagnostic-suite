#include "diag_tools_loader.h"

#include <stdlib.h>

#ifdef DIAG_TOOLS_LOADER_TESTING
#include "tests/host/diag_tools_loader_platform.h"
#else
#include <furi.h>
#include <furi/core/memmgr.h>
#include <furi/core/memmgr_heap.h>
#include <flipper_application/plugins/plugin_manager.h>
#include <loader/firmware_api/firmware_api.h>
#include <storage/storage.h>
#endif

#define DIAG_TOOLS_PLUGIN_PATH APP_ASSETS_PATH("plugins/nfc_diag_tools.fal")
#define DIAG_TOOLS_MAX_FILE_SIZE (128u * 1024u)
/* mntm-012 build: 12,714 mapped + 2,211 fast reloc bytes. Keep 4 KiB
   loader overhead and 12 KiB working reserve without mirroring RF's 40 KiB gate. */
#define DIAG_TOOLS_LOAD_FREE_HEAP (32u * 1024u)
#define DIAG_TOOLS_LOAD_MAX_BLOCK (12u * 1024u)
#define DIAG_TOOLS_READY_FREE_HEAP (12u * 1024u)
#define DIAG_TOOLS_READY_MAX_BLOCK (4u * 1024u)

struct DiagTools {
    PluginManager* manager;
    const DiagToolsApi* api;
};

static void diag_tools_explain(FuriString* explanation, const char* text) {
    if(explanation) furi_string_set(explanation, text);
}

static bool diag_tools_api_valid(const DiagToolsApi* api) {
    return api && api->recommend && api->from_reader && api->from_fields &&
           api->resolve_directory && api->current_load && api->save_reader_profile &&
           api->find_similar && api->choose;
}

DiagTools* diag_tools_open(Storage* storage, FuriString* explanation) {
    if(explanation) furi_string_reset(explanation);
    if(!storage) {
        diag_tools_explain(explanation, "Tools plugin: invalid storage.");
        return NULL;
    }

    FileInfo info;
    const FS_Error stat_error = storage_common_stat(storage, DIAG_TOOLS_PLUGIN_PATH, &info);
    if(stat_error != FSE_OK) {
        if(explanation) {
            furi_string_printf(
                explanation,
                "Tools plugin unavailable: %s (FS_Error %u)\n%s",
                storage_error_get_desc(stat_error),
                (unsigned)stat_error,
                DIAG_TOOLS_PLUGIN_PATH);
        }
        return NULL;
    }
    if(file_info_is_dir(&info) || !info.size || info.size > DIAG_TOOLS_MAX_FILE_SIZE) {
        diag_tools_explain(explanation, "Tools plugin has invalid size or type.");
        return NULL;
    }

    const size_t free_heap = memmgr_get_free_heap();
    const size_t max_block = memmgr_heap_get_max_free_block();
    if(free_heap < DIAG_TOOLS_LOAD_FREE_HEAP || max_block < DIAG_TOOLS_LOAD_MAX_BLOCK) {
        if(explanation) {
            furi_string_printf(
                explanation,
                "Tools need free RAM. Free %u, largest %u.",
                (unsigned)free_heap,
                (unsigned)max_block);
        }
        return NULL;
    }

    DiagTools* tools = malloc(sizeof(DiagTools));
    if(!tools) {
        diag_tools_explain(explanation, "Tools loader allocation failed.");
        return NULL;
    }
    tools->api = NULL;
    tools->manager = plugin_manager_alloc(
        DIAG_TOOLS_PLUGIN_APP_ID,
        DIAG_TOOLS_PLUGIN_API_VERSION,
        firmware_api_interface);

    const PluginManagerError load_error =
        plugin_manager_load_single(tools->manager, DIAG_TOOLS_PLUGIN_PATH);
    if(load_error != PluginManagerErrorNone ||
       plugin_manager_get_count(tools->manager) != 1u) {
        const char* message = "Tools plugin load failed.";
        if(load_error == PluginManagerErrorApplicationIdMismatch) {
            message = "Tools plugin app ID mismatch.";
        } else if(load_error == PluginManagerErrorAPIVersionMismatch) {
            message = "Tools plugin API mismatch.";
        }
        diag_tools_explain(explanation, message);
        diag_tools_close(tools);
        return NULL;
    }

    tools->api = plugin_manager_get_ep(tools->manager, 0u);
    if(!diag_tools_api_valid(tools->api)) {
        diag_tools_explain(explanation, "Tools plugin API is incomplete.");
        diag_tools_close(tools);
        return NULL;
    }
    if(memmgr_get_free_heap() < DIAG_TOOLS_READY_FREE_HEAP ||
       memmgr_heap_get_max_free_block() < DIAG_TOOLS_READY_MAX_BLOCK) {
        diag_tools_explain(explanation, "Tools plugin left insufficient working RAM.");
        diag_tools_close(tools);
        return NULL;
    }
    return tools;
}

const DiagToolsApi* diag_tools_api(DiagTools* tools) {
    return tools ? tools->api : NULL;
}

void diag_tools_close(DiagTools* tools) {
    if(!tools) return;
    if(tools->manager) plugin_manager_free(tools->manager);
    free(tools);
}
