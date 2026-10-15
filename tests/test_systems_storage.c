#include "../diag_systems.h"
#include "host/diag_systems_platform.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROOT DIAG_SYSTEM_UNGROUPED_DIRECTORY
#define CURRENT ROOT "/current_system.txt"
#define TEMP ROOT "/current_system.tmp"
#define BACKUP ROOT "/current_system.bak"

typedef enum {OpOpen, OpRead, OpWrite, OpSync, OpClose, OpRemove, OpRename} Operation;
typedef struct {bool exists; size_t size; unsigned char data[64];} Entry;
typedef struct {Operation operation; const char* source; const char* destination; FS_Error error; bool used;} Fault;
static Entry entries[3];
static const char* const paths[] = {CURRENT, TEMP, BACKUP};
static Fault faults[3];
static size_t fault_count;
static unsigned handles;
struct File {int index; size_t position; bool opened; FS_Error error;};
static Storage storage;
static FuriString explanation;

static int entry_index(const char* path) {
    for(int i=0; i<3; ++i) if(!strcmp(path, paths[i])) return i;
    assert(!"Unexpected test path"); return -1;
}
static FS_Error fault(Operation operation, const char* source, const char* destination) {
    for(size_t i=0;i<fault_count;++i) {
        Fault* f=&faults[i];
        if(!f->used && f->operation==operation && !strcmp(f->source,source) &&
           (!f->destination || (destination && !strcmp(f->destination,destination)))) {
            f->used=true; return f->error;
        }
    }
    return FSE_OK;
}
static void inject(Operation op, const char* path, const char* destination, FS_Error error) {
    assert(fault_count<3); faults[fault_count++]=(Fault){op,path,destination,error,false};
}
static void put(const char* path, const char* content) {
    Entry* e=&entries[entry_index(path)]; e->exists=true; e->size=strlen(content);
    assert(e->size<sizeof(e->data)); memcpy(e->data,content,e->size);
}
static void content(const char* path, const char* expected) {
    Entry* e=&entries[entry_index(path)]; assert(e->exists);
    assert(e->size==strlen(expected) && !memcmp(e->data,expected,e->size));
}
static void reset(void) {
    assert(!handles); memset(entries,0,sizeof(entries)); memset(faults,0,sizeof(faults));
    fault_count=0; explanation.text[0]='\0';
}
static void faults_used(void) {for(size_t i=0;i<fault_count;++i) assert(faults[i].used); assert(!handles);}
static void error_text(const char* phase, FS_Error error, const char* path) {
    char code[32]; snprintf(code,sizeof(code),"FS_Error %u",(unsigned)error);
    assert(strstr(explanation.text,phase) && strstr(explanation.text,code) && strstr(explanation.text,path));
}
File* storage_file_alloc(Storage* ignored) {
    (void)ignored; File* f=calloc(1,sizeof(*f)); assert(f); f->index=-1; ++handles; return f;
}
void storage_file_free(File* file) {assert(file && !file->opened && handles); --handles; free(file);}
bool storage_file_open(File* f,const char* path,FS_AccessMode access,FS_OpenMode mode) {
    (void)access; f->index=entry_index(path); f->error=fault(OpOpen,path,NULL);
    if(f->error) return false;
    Entry* e=&entries[f->index];
    if(mode==FSOM_OPEN_EXISTING && !e->exists) {f->error=FSE_NOT_EXIST;return false;}
    if(mode==FSOM_CREATE_NEW && e->exists) {f->error=FSE_EXIST;return false;}
    if(mode==FSOM_CREATE_ALWAYS || mode==FSOM_CREATE_NEW) {e->exists=true;e->size=0;}
    f->opened=true; f->position=0; return true;
}
bool storage_file_close(File* f) {
    if(!f->opened) {f->error=FSE_INVALID_PARAMETER;return false;}
    f->opened=false; f->error=fault(OpClose,paths[f->index],NULL); return f->error==FSE_OK;
}
FS_Error storage_file_get_error(File* f) {return f->error;}
uint64_t storage_file_size(File* f) {assert(f->opened);return entries[f->index].size;}
size_t storage_file_read(File* f,void* buffer,size_t size) {
    assert(f->opened); f->error=fault(OpRead,paths[f->index],NULL); if(f->error)return 0;
    Entry* e=&entries[f->index];if(size>e->size-f->position)size=e->size-f->position;
    memcpy(buffer,e->data+f->position,size);f->position+=size;return size;
}
size_t storage_file_write(File* f,const void* buffer,size_t size) {
    assert(f->opened && size<=sizeof(entries[0].data));
    f->error=fault(OpWrite,paths[f->index],NULL);if(f->error)size/=2;
    Entry* e=&entries[f->index];memcpy(e->data,buffer,size);e->size=size;return size;
}
bool storage_file_sync(File* f) {assert(f->opened);f->error=fault(OpSync,paths[f->index],NULL);return !f->error;}
bool storage_file_exists(Storage* s,const char* path) {(void)s;return entries[entry_index(path)].exists;}
FS_Error storage_common_remove(Storage* s,const char* path) {
    (void)s;FS_Error e=fault(OpRemove,path,NULL);if(e)return e;
    Entry* entry=&entries[entry_index(path)];if(!entry->exists)return FSE_NOT_EXIST;entry->exists=false;return FSE_OK;
}
FS_Error storage_common_rename_safe(Storage* s,const char* from,const char* to) {
    (void)s;FS_Error e=fault(OpRename,from,to);if(e)return e;
    Entry* a=&entries[entry_index(from)];Entry* b=&entries[entry_index(to)];
    if(!a->exists)return FSE_NOT_EXIST;if(b->exists)return FSE_EXIST;
    *b=*a;a->exists=false;return FSE_OK;
}
bool storage_simply_remove(Storage* s,const char* path) {return storage_common_remove(s,path)==FSE_OK;}
FS_Error storage_common_stat(Storage* s,const char* path,FileInfo* info) {
    (void)s;Entry* e=&entries[entry_index(path)];if(!e->exists)return FSE_NOT_EXIST;
    *info=(FileInfo){.size=e->size};return FSE_OK;
}
bool file_info_is_dir(const FileInfo* info) {return (info->flags&FSF_DIRECTORY)!=0;}
bool storage_dir_open(File* f,const char* path) {(void)f;(void)path;assert(!"Directory outside current-state test scope");return false;}
bool storage_dir_close(File* f) {(void)f;assert(!"Unexpected directory close");return false;}
bool storage_dir_read(File* f,FileInfo* i,char* n,uint16_t z) {(void)f;(void)i;(void)n;(void)z;assert(!"Unexpected directory read");return false;}
const char* storage_error_get_desc(FS_Error error) {
    switch(error) {case FSE_DENIED:return "Denied";case FSE_NOT_READY:return "Not ready";case FSE_NOT_EXIST:return "Not found";default:return "Other";}
}
const char* diag_file_status_string(DiagFileStatus status) {(void)status;return "status";}
DiagFileStatus diag_files_ensure_directory(Storage* s,const char* path,FuriString* text) {
    (void)s;(void)text;assert(!strcmp(path,ROOT));return DiagFileStatusOk;
}
void furi_string_printf(FuriString* string,const char* format,...) {
    va_list args;va_start(args,format);int size=vsnprintf(string->text,sizeof(string->text),format,args);va_end(args);
    assert(size>=0 && (size_t)size<sizeof(string->text));
}
void furi_string_cat_printf(FuriString* string,const char* format,...) {
    size_t used=strlen(string->text);va_list args;va_start(args,format);
    int size=vsnprintf(string->text+used,sizeof(string->text)-used,format,args);va_end(args);
    assert(size>=0 && (size_t)size<sizeof(string->text)-used);
}
static void test_success_and_noncommit_failures(void) {
    reset();put(CURRENT,"Old\n");
    assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusOk);
    content(CURRENT,"New\n");assert(!entries[1].exists && !entries[2].exists && !handles);
    const Operation ops[]={OpOpen,OpWrite,OpSync,OpClose};
    for(size_t i=0;i<sizeof(ops)/sizeof(ops[0]);++i) {
        reset();put(CURRENT,"Old\n");inject(ops[i],TEMP,NULL,FSE_DENIED);
        assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusIo);
        content(CURRENT,"Old\n");error_text("Write current system",FSE_DENIED,TEMP);faults_used();
        assert((strstr(explanation.text,"Temporary retained:")!=NULL)==entries[1].exists);
    }
}
static void test_commit_faults_and_recovery(void) {
    reset();put(CURRENT,"Old\n");put(BACKUP,"Older\n");inject(OpRemove,BACKUP,NULL,FSE_DENIED);
    assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusIo);
    content(CURRENT,"Old\n");content(BACKUP,"Older\n");content(TEMP,"New\n");
    error_text("Remove old system backup",FSE_DENIED,BACKUP);faults_used();
    reset();put(BACKUP,"Old\n");inject(OpRename,BACKUP,CURRENT,FSE_NOT_READY);
    assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusIo);
    content(BACKUP,"Old\n");assert(!entries[0].exists);error_text("Restore system backup",FSE_NOT_READY,BACKUP);faults_used();
    reset();put(CURRENT,"Old\n");inject(OpRename,CURRENT,BACKUP,FSE_DENIED);
    assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusIo);
    content(CURRENT,"Old\n");content(TEMP,"New\n");error_text("Back up current system",FSE_DENIED,CURRENT);faults_used();
    reset();put(CURRENT,"Old\n");inject(OpRename,TEMP,CURRENT,FSE_DENIED);
    assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusIo);
    content(CURRENT,"Old\n");content(TEMP,"New\n");error_text("Publish current system",FSE_DENIED,TEMP);faults_used();
    reset();put(CURRENT,"Old\n");inject(OpRename,TEMP,CURRENT,FSE_DENIED);inject(OpRename,BACKUP,CURRENT,FSE_NOT_READY);
    assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusIo);
    assert(!entries[0].exists);content(BACKUP,"Old\n");content(TEMP,"New\n");
    error_text("Publish current system",FSE_DENIED,TEMP);assert(strstr(explanation.text,"Restore backup: FS_Error 1"));faults_used();
    char name[DIAG_SYSTEM_NAME_CAPACITY]="Unchanged";
    assert(diag_system_current_load(&storage,name,&explanation)==DiagFileStatusOk && !strcmp(name,"Old"));
    reset();put(CURRENT,"Old\n");inject(OpRemove,BACKUP,NULL,FSE_DENIED);
    assert(diag_system_current_save(&storage,"New",&explanation)==DiagFileStatusOk);
    content(CURRENT,"New\n");content(BACKUP,"Old\n");faults_used();
}
static void test_load_fallback_and_stability(void) {
    reset();put(CURRENT,"broken");put(BACKUP,"Backup\n");
    char name[DIAG_SYSTEM_NAME_CAPACITY]="Sentinel";
    assert(diag_system_current_load(&storage,name,&explanation)==DiagFileStatusOk && !strcmp(name,"Backup"));
    reset();put(CURRENT,"broken");put(BACKUP,"also broken");
    memset(name,0x5A,sizeof(name));strcpy(name,"Sentinel");
    char prior[sizeof(name)];memcpy(prior,name,sizeof(name));
    assert(diag_system_current_load(&storage,name,&explanation)==DiagFileStatusInvalidFormat && !memcmp(name,prior,sizeof(name)));
    reset();put(BACKUP,"Backup\n");inject(OpOpen,BACKUP,NULL,FSE_DENIED);
    assert(diag_system_current_load(&storage,name,&explanation)==DiagFileStatusIo && !memcmp(name,prior,sizeof(name)));
    error_text("Load current system",FSE_DENIED,BACKUP);faults_used();
    reset();put(CURRENT,"Current\n");inject(OpRead,CURRENT,NULL,FSE_NOT_READY);
    assert(diag_system_current_load(&storage,name,&explanation)==DiagFileStatusIo && !memcmp(name,prior,sizeof(name)));
    error_text("Load current system",FSE_NOT_READY,CURRENT);faults_used();
    reset();put(CURRENT,"Current\n");put(BACKUP,"Backup\n");inject(OpClose,CURRENT,NULL,FSE_DENIED);
    assert(diag_system_current_load(&storage,name,&explanation)==DiagFileStatusOk && !strcmp(name,"Backup"));faults_used();
}
int main(void) {
    test_success_and_noncommit_failures();test_commit_faults_and_recovery();test_load_fallback_and_stability();
    assert(!handles);puts("Native systems persistence fault checks passed");return 0;
}
