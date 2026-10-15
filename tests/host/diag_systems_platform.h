#pragma once
/* The real native branch uses the pinned SDK's actual file enums and FileInfo.
   Only the transport and FuriString implementation are replaced by the test. */
#include <filesystem_api_defines.h>
#include <stddef.h>
#include "../../diag_files.h"
struct Storage { unsigned unused; };
struct FuriString { char text[1536]; };
File* storage_file_alloc(Storage* storage);
void storage_file_free(File* file);
bool storage_file_open(File*, const char*, FS_AccessMode, FS_OpenMode);
bool storage_file_close(File*);
FS_Error storage_file_get_error(File*);
uint64_t storage_file_size(File*);
size_t storage_file_read(File*, void*, size_t);
size_t storage_file_write(File*, const void*, size_t);
bool storage_file_sync(File*);
bool storage_file_exists(Storage*, const char*);
FS_Error storage_common_remove(Storage*, const char*);
FS_Error storage_common_rename_safe(Storage*, const char*, const char*);
FS_Error storage_common_stat(Storage*, const char*, FileInfo*);
bool storage_simply_remove(Storage*, const char*);
bool storage_dir_open(File*, const char*);
bool storage_dir_close(File*);
bool storage_dir_read(File*, FileInfo*, char*, uint16_t);
const char* storage_error_get_desc(FS_Error);
void furi_string_printf(FuriString*, const char*, ...);
void furi_string_cat_printf(FuriString*, const char*, ...);
