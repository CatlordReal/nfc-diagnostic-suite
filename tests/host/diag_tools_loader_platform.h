#ifndef DIAG_TOOLS_LOADER_PLATFORM_H
#define DIAG_TOOLS_LOADER_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APP_ASSETS_PATH(path) "/assets/" path

typedef enum {
    FSE_OK = 0,
    FSE_NOT_READY,
    FSE_EXIST,
    FSE_NOT_EXIST,
    FSE_INVALID_PARAMETER,
    FSE_DENIED,
    FSE_INVALID_NAME,
    FSE_INTERNAL,
    FSE_NOT_IMPLEMENTED,
    FSE_ALREADY_OPEN,
} FS_Error;

typedef struct {
    uint8_t flags;
    uint64_t size;
} FileInfo;

typedef enum {
    PluginManagerErrorNone = 0,
    PluginManagerErrorLoaderError,
    PluginManagerErrorApplicationIdMismatch,
    PluginManagerErrorAPIVersionMismatch,
} PluginManagerError;

typedef struct PluginManager PluginManager;
typedef struct ElfApiInterface ElfApiInterface;

extern const ElfApiInterface* const firmware_api_interface;

FS_Error storage_common_stat(Storage* storage, const char* path, FileInfo* info);
const char* storage_error_get_desc(FS_Error error);
bool file_info_is_dir(const FileInfo* info);
size_t memmgr_get_free_heap(void);
size_t memmgr_heap_get_max_free_block(void);
void furi_string_reset(FuriString* string);
void furi_string_set(FuriString* string, const char* text);
void furi_string_printf(FuriString* string, const char* format, ...);
PluginManager* plugin_manager_alloc(
    const char* application_id,
    uint32_t api_version,
    const ElfApiInterface* api_interface);
void plugin_manager_free(PluginManager* manager);
PluginManagerError plugin_manager_load_single(PluginManager* manager, const char* path);
uint32_t plugin_manager_get_count(PluginManager* manager);
const void* plugin_manager_get_ep(PluginManager* manager, uint32_t index);

#endif
