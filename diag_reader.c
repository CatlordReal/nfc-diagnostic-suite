#include "diag_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define READER_MAX_PENDING 16u
#define READER_LINE_CAPACITY 192u
#define READER_LOG_LIMIT (1024u * 1024u)

/* Probe configuration stays separate from observed card evidence. Shared with
   host regression tests so fingerprint context matches the actual listener. */
static bool reader_configure_stimulus(
    DiagReaderMode mode, const DiagIsoAIdentity* source, const uint8_t random_uid[4],
    DiagIsoAIdentity* result, bool* synthetic) {
    if(!result || !synthetic || (unsigned)mode > DiagReaderModeClassic) return false;
    if(source && (!source->present ||
       (source->uid_size != 4u && source->uid_size != 7u && source->uid_size != 10u) ||
       (mode == DiagReaderModeClassic && source->uid_size == 10u))) return false;
    memset(result, 0, sizeof(*result));
    *synthetic = false;
    if(mode == DiagReaderModeField) return true;
    if(source) *result = *source;
    else {
        if(!random_uid) return false;
        result->present = true;
        result->uid_size = 4;
        memcpy(result->uid, random_uid, 4);
        result->uid[0] = 0x08;
        result->atqa[0] = 0x04;
        *synthetic = true;
    }
    result->cascade_count = result->uid_size == 4u ? 1u : result->uid_size == 7u ? 2u : 3u;
    if(mode == DiagReaderModeClassic) {
        result->sak = 0x18;
        result->atqa[0] = result->uid_size == 7u ? 0x42 : 0x02;
        result->atqa[1] = 0;
    }
    return true;
}

typedef struct {
    uint32_t cuid;
    uint8_t sector;
    bool key_b;
    uint32_t nt;
    uint32_t nr;
    uint32_t ar;
} ReaderTranscript;

typedef struct {
    ReaderTranscript first;
    ReaderTranscript second;
} ReaderPair;

typedef enum {
    ReaderEventFieldOn,
    ReaderEventFieldOff,
    ReaderEventSelected,
    ReaderEventRx,
    ReaderEventError,
    ReaderEventSampleOff,
    ReaderEventSampleOn,
    ReaderEventAuthPart,
    ReaderEventAuthFull,
} ReaderEventType;

typedef struct {
    ReaderEventType type;
    uint32_t elapsed_ms;
    uint16_t frame_bits;
    uint8_t opcode;
    ReaderTranscript transcript;
} ReaderEvent;

typedef struct {
    DiagModel model;
    DiagReaderStats stats;
    ReaderTranscript pending[READER_MAX_PENDING];
    size_t pending_count;
    ReaderPair pairs[DIAG_READER_MAX_PAIRS];
    size_t pair_count;
    bool field_known;
    bool finished;
} ReaderCore;

const char* diag_reader_mode_name(DiagReaderMode mode) {
    switch(mode) {
    case DiagReaderModeField: return "Reader field monitor";
    case DiagReaderModeTypeA: return "Type A reader probe";
    case DiagReaderModeClassic: return "Classic reader transcripts";
    default: return "Unknown reader mode";
    }
}

static void reader_log(ReaderCore* core, DiagLogLevel level, DiagStage stage, const char* text) {
    diag_model_add_log_at(&core->model, level, stage, core->stats.elapsed_ms, text);
}

static void reader_core_init(ReaderCore* core, DiagReaderMode mode) {
    memset(core, 0, sizeof(*core));
    diag_model_init(&core->model, DiagProvenanceLive);
    core->stats.mode = mode;
    core->stats.inconclusive = true;
    core->stats.field_available = mode != DiagReaderModeClassic;
    core->stats.selection_available = mode == DiagReaderModeTypeA;
    core->stats.rx_total_available = mode == DiagReaderModeTypeA;
    core->stats.sample_period_ms = mode == DiagReaderModeField ? DIAG_READER_FIELD_SAMPLE_MS : 0;
    diag_model_set_product_metadata(&core->model, diag_reader_mode_name(mode), "Reader observations; no brand/model inference");
    reader_log(core, DiagLogInfo, DiagStageNone, "Reader identity is unknown; no brand/model is inferred from protocol traffic");
}

static bool reader_same_key(const ReaderTranscript* left, const ReaderTranscript* right) {
    return left->cuid == right->cuid && left->sector == right->sector && left->key_b == right->key_b;
}

static bool reader_same_transcript(const ReaderTranscript* left, const ReaderTranscript* right) {
    return reader_same_key(left, right) && left->nt == right->nt &&
           left->nr == right->nr && left->ar == right->ar;
}

static bool reader_pair_equal(const ReaderPair* left, const ReaderPair* right) {
    return (reader_same_transcript(&left->first, &right->first) &&
            reader_same_transcript(&left->second, &right->second)) ||
           (reader_same_transcript(&left->first, &right->second) &&
            reader_same_transcript(&left->second, &right->first));
}

static bool reader_transcript_seen(const ReaderCore* core, const ReaderTranscript* transcript) {
    for(size_t index = 0; index < core->pending_count; ++index) {
        if(reader_same_transcript(&core->pending[index], transcript)) return true;
    }
    for(size_t index = 0; index < core->pair_count; ++index) {
        if(reader_same_transcript(&core->pairs[index].first, transcript) ||
           reader_same_transcript(&core->pairs[index].second, transcript)) return true;
    }
    return false;
}

static void reader_collect(ReaderCore* core, const ReaderTranscript* transcript) {
    if(reader_transcript_seen(core, transcript)) {
        ++core->stats.transcript_duplicates;
        return;
    }
    ++core->stats.transcripts_collected;
    diag_model_confirm_protocol(&core->model, DiagProtocolMfClassic, true);
    diag_model_mark_stage_success(&core->model, DiagStageProtocolRead);
    for(size_t index = 0; index < core->pending_count; ++index) {
        const ReaderTranscript* first = &core->pending[index];
        if(!reader_same_key(first, transcript)) continue;
        /* Full replay was rejected above; shared components (including static Nt)
           remain valid inputs to the native MFKey workflow. */
        if(core->pair_count == DIAG_READER_MAX_PAIRS) {
            ++core->stats.transcript_rejected;
            return;
        }
        ReaderPair pair = {.first = *first, .second = *transcript};
        for(size_t pair_index = 0; pair_index < core->pair_count; ++pair_index) {
            if(reader_pair_equal(&pair, &core->pairs[pair_index])) {
                ++core->stats.transcript_duplicates;
                return;
            }
        }
        core->pairs[core->pair_count++] = pair;
        core->stats.nonce_pairs = (uint32_t)core->pair_count;
        core->stats.inconclusive = false;
        char message[DIAG_LOG_MESSAGE_CAPACITY];
        snprintf(message, sizeof(message), "Distinct Classic pair: sector %u, key %c; recovery not performed",
                 transcript->sector, transcript->key_b ? 'B' : 'A');
        reader_log(core, DiagLogSuccess, DiagStageMetadataRead, message);
        diag_model_mark_stage_success(&core->model, DiagStageMetadataRead);
        return;
    }
    if(core->pending_count < READER_MAX_PENDING) {
        core->pending[core->pending_count++] = *transcript;
        reader_log(core, DiagLogInfo, DiagStageProtocolRead,
                   "Complete Nt/Nr/Ar sample captured; distinct matching exchange still needed");
    } else {
        ++core->stats.transcript_rejected;
    }
}

static uint32_t reader_be32(const uint8_t bytes[4]) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

/* Both live listener callbacks and host tests use this exact frame boundary. */
static bool reader_auth_event(
    ReaderEvent* event, uint32_t elapsed_ms, uint32_t cuid, uint8_t block, bool key_b,
    const uint8_t nt[4], const uint8_t* reader_frame, size_t reader_frame_size) {
    if(!event || !nt || !reader_frame || reader_frame_size != 8) return false;
    memset(event, 0, sizeof(*event));
    event->type = ReaderEventAuthPart;
    event->elapsed_ms = elapsed_ms;
    event->frame_bits = 64;
    event->transcript = (ReaderTranscript){
        .cuid = cuid,
        .sector = block < 128 ? block / 4 : (uint8_t)(32 + (block - 128) / 16),
        .key_b = key_b,
        .nt = reader_be32(nt),
        .nr = reader_be32(reader_frame),
        .ar = reader_be32(reader_frame + 4),
    };
    return true;
}

static void reader_field(ReaderCore* core, const ReaderEvent* event, bool on, bool sampled) {
    if(sampled) ++core->stats.samples;
    bool changed = !core->field_known || core->stats.field_present != on;
    if(!changed) return;
    if(core->field_known) {
        uint32_t duration = event->elapsed_ms - core->stats.last_field_change_ms;
        if(core->stats.field_present) core->stats.field_on_ms += duration;
        else core->stats.field_off_ms += duration;
    }
    bool first_observation = !core->field_known;
    core->field_known = true;
    core->stats.field_present = on;
    core->stats.last_field_change_ms = event->elapsed_ms;
    if(on) {
        ++core->stats.field_on_count;
        core->stats.field_observed = true;
        diag_model_mark_stage_success(&core->model, DiagStageFieldStarted);
    } else if(!first_observation || !sampled) {
        ++core->stats.field_off_count;
    }
    reader_log(core, DiagLogInfo, DiagStageFieldStarted, on ? "External NFC field observed on" : "External NFC field observed off");
}

static void reader_request(ReaderCore* core, const ReaderEvent* event) {
    ++core->stats.rx_count;
    ++core->stats.request_count;
    if(core->stats.request_count == 1) {
        core->stats.first_request_ms = event->elapsed_ms;
    } else {
        uint32_t gap = event->elapsed_ms - core->stats.last_request_ms;
        if(core->stats.request_count == 2 || gap < core->stats.min_request_gap_ms) {
            core->stats.min_request_gap_ms = gap;
        }
        if(gap > core->stats.max_request_gap_ms) core->stats.max_request_gap_ms = gap;
    }
    core->stats.last_request_ms = event->elapsed_ms;
    if((event->opcode == 0x60 || event->opcode == 0x61) && event->frame_bits == 32) {
        ++core->stats.auth_request_count;
        diag_model_add_protocol_candidate(&core->model, DiagProtocolMfClassic);
    }
    if(core->stats.request_count <= 12) {
        char message[DIAG_LOG_MESSAGE_CAPACITY];
        snprintf(message, sizeof(message), "Reader request opcode=%02X, %u bits; payload not retained",
                 event->opcode, event->frame_bits);
        reader_log(core, DiagLogInfo, DiagStageProtocolRead, message);
    }
}

static void reader_process(ReaderCore* core, const ReaderEvent* event) {
    if(event->elapsed_ms > core->stats.elapsed_ms) core->stats.elapsed_ms = event->elapsed_ms;
    switch(event->type) {
    case ReaderEventFieldOn: reader_field(core, event, true, false); break;
    case ReaderEventFieldOff: reader_field(core, event, false, false); break;
    case ReaderEventSampleOn: reader_field(core, event, true, true); break;
    case ReaderEventSampleOff: reader_field(core, event, false, true); break;
    case ReaderEventSelected:
        ++core->stats.selection_count;
        core->stats.inconclusive = false;
        diag_model_confirm_protocol(&core->model, DiagProtocolIso14443_3a, true);
        diag_model_mark_stage_success(&core->model, DiagStageProtocolRead);
        reader_log(core, DiagLogSuccess, DiagStageProtocolRead, "Reader selected synthetic Type A identity; higher protocols remain unproven");
        break;
    case ReaderEventRx: reader_request(core, event); break;
    case ReaderEventAuthPart:
        ++core->stats.rx_count;
        ++core->stats.auth_request_count;
        reader_collect(core, &event->transcript);
        break;
    case ReaderEventAuthFull:
        ++core->stats.auth_full_count;
        reader_log(core, DiagLogInfo, DiagStageProtocolRead,
                   "Reader authenticated to synthetic RAM image; no real card secret was loaded");
        break;
    case ReaderEventError:
        ++core->stats.error_count;
        ++core->stats.transcript_rejected;
        reader_log(core, DiagLogWarning, DiagStageProtocolRead,
                   "Incomplete or unsupported reader event; no recovery transcript accepted");
        break;
    }
}

static void reader_snapshot_core(const ReaderCore* core, DiagModel* model, DiagReaderStats* stats) {
    if(model) *model = core->model;
    if(stats) {
        *stats = core->stats;
        if(core->field_known && !core->finished) {
            uint32_t duration = core->stats.elapsed_ms - core->stats.last_field_change_ms;
            if(core->stats.field_present) stats->field_on_ms += duration;
            else stats->field_off_ms += duration;
        }
    }
}

static size_t reader_pair_format(const ReaderPair* pair, char* output, size_t capacity) {
    if(!pair || !output || !capacity) return 0;
    int size = snprintf(output, capacity,
        "Sec %u key %c cuid %08lx nt0 %08lx nr0 %08lx ar0 %08lx nt1 %08lx nr1 %08lx ar1 %08lx\n",
        pair->first.sector, pair->first.key_b ? 'B' : 'A', (unsigned long)pair->first.cuid,
        (unsigned long)pair->first.nt, (unsigned long)pair->first.nr, (unsigned long)pair->first.ar,
        (unsigned long)pair->second.nt, (unsigned long)pair->second.nr, (unsigned long)pair->second.ar);
    return size > 0 && (size_t)size < capacity ? (size_t)size : 0;
}

static bool reader_literal(const char** cursor, const char* literal) {
    size_t size = strlen(literal);
    if(strncmp(*cursor, literal, size)) return false;
    *cursor += size;
    return true;
}

static bool reader_hex32(const char** cursor, uint32_t* value) {
    uint32_t number = 0;
    for(unsigned index = 0; index < 8; ++index) {
        unsigned char byte = (unsigned char)(*cursor)[index];
        if(!byte) return false;
        unsigned nibble;
        if(byte >= '0' && byte <= '9') nibble = byte - '0';
        else if(byte >= 'a' && byte <= 'f') nibble = byte - 'a' + 10;
        else if(byte >= 'A' && byte <= 'F') nibble = byte - 'A' + 10;
        else return false;
        number = (number << 4) | nibble;
    }
    *cursor += 8;
    *value = number;
    return true;
}

static bool reader_pair_parse(const char* text, ReaderPair* pair) {
    if(!text || !pair) return false;
    memset(pair, 0, sizeof(*pair));
    const char* cursor = text;
    if(!reader_literal(&cursor, "Sec ") || *cursor < '0' || *cursor > '9') return false;
    unsigned sector = *cursor++ - '0';
    if(*cursor >= '0' && *cursor <= '9') sector = sector * 10 + (*cursor++ - '0');
    if(sector > 39 || !reader_literal(&cursor, " key ")) return false;
    if(*cursor != 'A' && *cursor != 'B') return false;
    pair->first.sector = (uint8_t)sector;
    pair->first.key_b = *cursor++ == 'B';
    if(!reader_literal(&cursor, " cuid ") || !reader_hex32(&cursor, &pair->first.cuid) ||
       !reader_literal(&cursor, " nt0 ") || !reader_hex32(&cursor, &pair->first.nt) ||
       !reader_literal(&cursor, " nr0 ") || !reader_hex32(&cursor, &pair->first.nr) ||
       !reader_literal(&cursor, " ar0 ") || !reader_hex32(&cursor, &pair->first.ar) ||
       !reader_literal(&cursor, " nt1 ") || !reader_hex32(&cursor, &pair->second.nt) ||
       !reader_literal(&cursor, " nr1 ") || !reader_hex32(&cursor, &pair->second.nr) ||
       !reader_literal(&cursor, " ar1 ") || !reader_hex32(&cursor, &pair->second.ar)) return false;
    if(*cursor == '\r') ++cursor;
    if(*cursor == '\n') ++cursor;
    if(*cursor) return false;
    pair->second.cuid = pair->first.cuid;
    pair->second.sector = pair->first.sector;
    pair->second.key_b = pair->first.key_b;
    return !reader_same_transcript(&pair->first, &pair->second);
}

typedef struct {
    char line[READER_LINE_CAPACITY];
    size_t used;
    bool overlong;
    bool ends_in_newline;
    bool dictionary;
    uint32_t valid;
    uint32_t malformed;
    uint32_t oversized;
    void (*on_pair)(const ReaderPair* pair, void* context);
    void* context;
} ReaderLineScan;

static void reader_scan_line(ReaderLineScan* scan) {
    if(scan->overlong) {
        ++scan->oversized;
    } else if(scan->used) {
        scan->line[scan->used] = '\0';
        if(scan->dictionary) {
            size_t size = scan->used;
            if(size && scan->line[size - 1] == '\r') --size;
            if(scan->line[0] != '#') {
                bool valid = size == 12;
                for(size_t index = 0; valid && index < size; ++index) {
                    char byte = scan->line[index];
                    valid = (byte >= '0' && byte <= '9') ||
                            (byte >= 'a' && byte <= 'f') || (byte >= 'A' && byte <= 'F');
                }
                if(valid) ++scan->valid;
                else ++scan->malformed;
            }
        } else {
            ReaderPair pair;
            if(reader_pair_parse(scan->line, &pair)) {
                ++scan->valid;
                if(scan->on_pair) scan->on_pair(&pair, scan->context);
            } else {
                ++scan->malformed;
            }
        }
    }
    scan->used = 0;
    scan->overlong = false;
}

static void reader_scan_bytes(ReaderLineScan* scan, const uint8_t* data, size_t size) {
    for(size_t index = 0; index < size; ++index) {
        scan->ends_in_newline = data[index] == '\n';
        if(data[index] == '\n') reader_scan_line(scan);
        else if(!data[index]) scan->overlong = true;
        else if(scan->used < sizeof(scan->line) - 1) scan->line[scan->used++] = (char)data[index];
        else scan->overlong = true;
    }
}

#ifdef DIAG_READER_TESTING
bool diag_reader_test_stimulus(
    DiagReaderMode mode, const DiagIsoAIdentity* source, const uint8_t random_uid[4],
    DiagIsoAIdentity* result, bool* synthetic) {
    return reader_configure_stimulus(mode, source, random_uid, result, synthetic);
}

struct DiagReaderTest { ReaderCore core; };
DiagReaderTest* diag_reader_test_alloc(DiagReaderMode mode) {
    if(mode > DiagReaderModeClassic) return NULL;
    DiagReaderTest* instance = calloc(1, sizeof(*instance));
    if(instance) reader_core_init(&instance->core, mode);
    return instance;
}
void diag_reader_test_free(DiagReaderTest* instance) { free(instance); }
void diag_reader_test_event(
    DiagReaderTest* instance, DiagReaderTestEvent type, uint32_t elapsed_ms,
    uint8_t opcode, uint16_t frame_bits) {
    if(!instance || type > DiagReaderTestSampleOn) return;
    ReaderEvent event = {.type = (ReaderEventType)type, .elapsed_ms = elapsed_ms,
                         .opcode = opcode, .frame_bits = frame_bits};
    reader_process(&instance->core, &event);
}
bool diag_reader_test_auth_frame(
    DiagReaderTest* instance, uint32_t elapsed_ms, uint32_t cuid,
    uint8_t block, bool key_b, const uint8_t nt[4], const uint8_t* frame, size_t size) {
    if(!instance) return false;
    ReaderEvent event;
    if(!reader_auth_event(&event, elapsed_ms, cuid, block, key_b, nt, frame, size)) {
        event = (ReaderEvent){.type = ReaderEventError, .elapsed_ms = elapsed_ms};
        reader_process(&instance->core, &event);
        return false;
    }
    reader_process(&instance->core, &event);
    return true;
}
void diag_reader_test_snapshot(const DiagReaderTest* instance, DiagModel* model, DiagReaderStats* stats) {
    if(instance) reader_snapshot_core(&instance->core, model, stats);
}
size_t diag_reader_test_pair_line(const DiagReaderTest* instance, size_t index, char* output, size_t capacity) {
    return instance && index < instance->core.pair_count ?
           reader_pair_format(&instance->core.pairs[index], output, capacity) : 0;
}
bool diag_reader_test_pair_lines_equal(const char* left, const char* right) {
    ReaderPair first, second;
    return reader_pair_parse(left, &first) && reader_pair_parse(right, &second) && reader_pair_equal(&first, &second);
}
void diag_reader_test_library(const uint8_t* data, size_t size, DiagNonceLibraryInfo* info) {
    if(!info || (!data && size)) return;
    memset(info, 0, sizeof(*info));
    ReaderLineScan scan = {0};
    reader_scan_bytes(&scan, data, size);
    if(scan.used || scan.overlong) reader_scan_line(&scan);
    info->exists = true;
    info->size_bytes = size;
    info->valid_pair_lines = scan.valid;
    info->malformed_lines = scan.malformed;
    info->oversized_lines = scan.oversized;
}
#else
#include "diag_build.h"
#include <furi.h>
#include <furi_hal_nfc.h>
#include <furi_hal_random.h>
#include <furi_hal_rtc.h>
#include <nfc/nfc.h>
#include <nfc/nfc_listener.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/mf_classic/mf_classic_listener.h>
#include <storage/storage.h>
#include <toolbox/version.h>

#define READER_CANCEL (1u << 0)
#define READER_QUEUE_SIZE 32u

struct DiagReader {
    FuriMutex* mutex;
    FuriEventFlag* events;
    FuriMessageQueue* queue;
    FuriThread* worker;
    ReaderCore core;
    DiagIsoAIdentity identity;
    bool running;
    bool worker_started;
    uint32_t started_tick;
    uint32_t cuid;
    uint32_t queue_dropped;
};

static uint32_t reader_elapsed(const DiagReader* instance) {
    return (uint32_t)(((uint64_t)(furi_get_tick() - instance->started_tick) * 1000u) /
                      furi_kernel_get_tick_frequency());
}

static bool reader_cancelled(DiagReader* instance) {
    return (furi_event_flag_get(instance->events) & READER_CANCEL) != 0;
}

static void reader_publish(DiagReader* instance, const ReaderEvent* event) {
    if(furi_message_queue_put(instance->queue, event, 0) != FuriStatusOk) {
        __atomic_fetch_add(&instance->queue_dropped, 1u, __ATOMIC_RELAXED);
    }
}

/* Raw Type A monitoring records only event metadata and a command byte, never
   reader payload, encrypted data, or a purported manufacturer fingerprint. */
static NfcCommand reader_type_a_callback(NfcEvent nfc_event, void* context) {
    DiagReader* instance = context;
    if(reader_cancelled(instance)) return NfcCommandStop;
    ReaderEvent event = {.elapsed_ms = reader_elapsed(instance)};
    switch(nfc_event.type) {
    case NfcEventTypeFieldOn: event.type = ReaderEventFieldOn; break;
    case NfcEventTypeFieldOff: event.type = ReaderEventFieldOff; break;
    case NfcEventTypeListenerActivated: event.type = ReaderEventSelected; break;
    case NfcEventTypeRxEnd:
        event.type = ReaderEventRx;
        event.frame_bits = (uint16_t)bit_buffer_get_size(nfc_event.data.buffer);
        if(event.frame_bits >= 8) event.opcode = bit_buffer_get_byte(nfc_event.data.buffer, 0);
        reader_publish(instance, &event);
        return NfcCommandReset;
    default: return NfcCommandContinue;
    }
    reader_publish(instance, &event);
    return NfcCommandContinue;
}

static NfcCommand reader_classic_callback(NfcGenericEvent generic_event, void* context) {
    DiagReader* instance = context;
    if(reader_cancelled(instance)) return NfcCommandStop;
    if(generic_event.protocol != NfcProtocolMfClassic || !generic_event.event_data) {
        ReaderEvent event = {.type = ReaderEventError, .elapsed_ms = reader_elapsed(instance)};
        reader_publish(instance, &event);
        return NfcCommandContinue;
    }
    const MfClassicListenerEvent* source = generic_event.event_data;
    ReaderEvent event;
    if(source->type == MfClassicListenerEventTypeAuthContextPartCollected && source->data) {
        const MfClassicAuthContext* sample = &source->data->auth_context;
        uint8_t frame[8];
        memcpy(frame, sample->nr.data, 4);
        memcpy(frame + 4, sample->ar.data, 4);
        if(sample->key_type != MfClassicKeyTypeA && sample->key_type != MfClassicKeyTypeB) {
            event = (ReaderEvent){.type = ReaderEventError, .elapsed_ms = reader_elapsed(instance)};
        } else {
            reader_auth_event(&event, reader_elapsed(instance), instance->cuid,
                               sample->block_num, sample->key_type == MfClassicKeyTypeB,
                               sample->nt.data, frame, sizeof(frame));
        }
    } else if(source->type == MfClassicListenerEventTypeAuthContextFullCollected) {
        event = (ReaderEvent){.type = ReaderEventAuthFull, .elapsed_ms = reader_elapsed(instance)};
    } else {
        event = (ReaderEvent){.type = ReaderEventError, .elapsed_ms = reader_elapsed(instance)};
    }
    reader_publish(instance, &event);
    /* This SDK ignores the Classic callback's return inside authentication.
       Cancellation is therefore performed by the owning worker's stop/join. */
    return NfcCommandContinue;
}

static void reader_drain(DiagReader* instance) {
    ReaderEvent event;
    while(furi_message_queue_get(instance->queue, &event, 0) == FuriStatusOk) {
        furi_mutex_acquire(instance->mutex, FuriWaitForever);
        reader_process(&instance->core, &event);
        furi_mutex_release(instance->mutex);
    }
}

static void reader_native_error(DiagReader* instance, const char* domain, int32_t code) {
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    ++instance->core.stats.error_count;
    diag_model_set_error(&instance->core.model, domain, code);
    char message[DIAG_LOG_MESSAGE_CAPACITY];
    snprintf(message, sizeof(message), "%s error=%ld; reader result incomplete", domain, (long)code);
    reader_log(&instance->core, DiagLogError, instance->core.model.last_successful_stage, message);
    furi_mutex_release(instance->mutex);
}

typedef struct {
    const ReaderPair* pairs;
    size_t count;
    bool* duplicates;
} ReaderPairMatches;

static void reader_nonce_match(const ReaderPair* existing, void* context) {
    ReaderPairMatches* matches = context;
    for(size_t index = 0; index < matches->count; ++index) {
        if(reader_pair_equal(existing, &matches->pairs[index])) matches->duplicates[index] = true;
    }
}

static int32_t reader_scan_file(File* file, uint64_t limit, bool complete_file, ReaderLineScan* scan) {
    uint8_t buffer[256];
    uint64_t consumed = 0;
    while(consumed < limit) {
        size_t wanted = limit - consumed < sizeof(buffer) ? (size_t)(limit - consumed) : sizeof(buffer);
        uint16_t received = storage_file_read(file, buffer, wanted);
        if(received != wanted) {
            int32_t error = storage_file_get_error(file);
            return error != FSE_OK ? error : FSE_INTERNAL;
        }
        reader_scan_bytes(scan, buffer, received);
        consumed += received;
    }
    if(complete_file && (scan->used || scan->overlong)) reader_scan_line(scan);
    return FSE_OK;
}

/* No I/O occurs in an RF callback. The worker calls this only after stop/join
   and HAL release. OPEN_APPEND preserves every existing byte; no truncation,
   rewrite, or native-log cleanup is performed. An I/O failure can leave a new
   partial tail, which is reported rather than deleting existing evidence. */
static int32_t reader_append_pairs(
    const ReaderPair* pairs, size_t pair_count, uint32_t* saved, uint32_t* already_saved) {
    *saved = 0;
    *already_saved = 0;
    if(!pair_count) return 0;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage_simply_mkdir(storage, EXT_PATH("nfc"))) {
        furi_record_close(RECORD_STORAGE);
        return FSE_NOT_READY;
    }
    File* file = storage_file_alloc(storage);
    bool duplicates[DIAG_READER_MAX_PAIRS] = {0};
    int32_t error = FSE_OK;
    bool ends_in_newline = true;
    /* Hold one storage handle throughout scan and append. The storage service
       rejects competing opens, so another app cannot change the log in between. */
    if(!storage_file_open(file, DIAG_READER_NONCE_LOG_PATH, FSAM_READ_WRITE, FSOM_OPEN_APPEND)) {
        error = storage_file_get_error(file);
        if(error == FSE_OK) error = FSE_INTERNAL;
        goto cleanup;
    }
    uint64_t original_size = storage_file_size(file);
    if(original_size > READER_LOG_LIMIT) {
        /* Application bound, deliberately outside the FS_Error namespace. */
        error = -1;
        goto cleanup;
    }
    if(!storage_file_seek(file, 0, true)) {
        error = FSE_INTERNAL;
        goto cleanup;
    }
    ReaderPairMatches matches = {.pairs = pairs, .count = pair_count, .duplicates = duplicates};
    ReaderLineScan scan = {.on_pair = reader_nonce_match, .context = &matches};
    error = reader_scan_file(file, original_size, true, &scan);
    ends_in_newline = !original_size || scan.ends_in_newline;
    if(error != FSE_OK) goto cleanup;
    size_t to_save = 0;
    for(size_t index = 0; index < pair_count; ++index) {
        if(duplicates[index]) ++*already_saved;
        else ++to_save;
    }
    if(!to_save) goto cleanup;
    if(!storage_file_seek(file, (uint32_t)original_size, true) ||
       storage_file_tell(file) != original_size) {
        error = FSE_INTERNAL;
        goto cleanup;
    }
    if(!ends_in_newline && storage_file_write(file, "\n", 1) != 1) {
        error = storage_file_get_error(file);
        if(error == FSE_OK) error = FSE_INTERNAL;
        goto cleanup;
    }
    for(size_t index = 0; index < pair_count; ++index) {
        if(duplicates[index]) continue;
        char line[READER_LINE_CAPACITY];
        size_t size = reader_pair_format(&pairs[index], line, sizeof(line));
        if(!size || storage_file_write(file, line, size) != size || !storage_file_sync(file)) {
            error = storage_file_get_error(file);
            if(error == FSE_OK) error = FSE_INTERNAL;
            goto cleanup;
        }
        ++*saved;
    }
cleanup:
    if(storage_file_is_open(file) && !storage_file_close(file) && error == FSE_OK) {
        error = storage_file_get_error(file);
        if(error == FSE_OK) error = FSE_INTERNAL;
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return error;
}

static int32_t reader_library_scan(
    Storage* storage, const char* path, bool dictionary, ReaderLineScan* scan,
    bool* exists, uint64_t* size, bool* truncated) {
    *exists = storage_file_exists(storage, path);
    *size = 0;
    *truncated = false;
    if(!*exists) return FSE_OK;
    File* file = storage_file_alloc(storage);
    int32_t error = FSE_OK;
    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        error = storage_file_get_error(file);
        if(error == FSE_OK) error = FSE_INTERNAL;
    } else {
        *size = storage_file_size(file);
        *truncated = *size > READER_LOG_LIMIT;
        scan->dictionary = dictionary;
        error = reader_scan_file(file, *truncated ? READER_LOG_LIMIT : *size, !*truncated, scan);
    }
    if(storage_file_is_open(file) && !storage_file_close(file) && error == FSE_OK) {
        error = storage_file_get_error(file);
        if(error == FSE_OK) error = FSE_INTERNAL;
    }
    storage_file_free(file);
    return error;
}

bool diag_reader_library_info(Storage* storage, DiagNonceLibraryInfo* info, FuriString* explanation) {
    if(!storage || !info) return false;
    memset(info, 0, sizeof(*info));
    ReaderLineScan scan = {0};
    int32_t error = reader_library_scan(storage, DIAG_READER_NONCE_LOG_PATH, false, &scan,
        &info->exists, &info->size_bytes, &info->truncated);
    info->valid_pair_lines = scan.valid;
    info->malformed_lines = scan.malformed;
    info->oversized_lines = scan.oversized;
    bool truncated;
    uint64_t size;
    ReaderLineScan dictionary = {0};
    int32_t dictionary_error = reader_library_scan(storage, EXT_PATH("nfc/assets/mf_classic_dict.nfc"),
        true, &dictionary, &info->system_dictionary_exists, &size, &truncated);
    info->system_dictionary_complete = info->system_dictionary_exists && !truncated && dictionary_error == FSE_OK;
    info->system_dictionary_entries = dictionary.valid;
    if(!error) error = dictionary_error;
    memset(&dictionary, 0, sizeof(dictionary));
    dictionary_error = reader_library_scan(storage, EXT_PATH("nfc/assets/mf_classic_dict_user.nfc"),
        true, &dictionary, &info->user_dictionary_exists, &size, &truncated);
    info->user_dictionary_complete = info->user_dictionary_exists && !truncated && dictionary_error == FSE_OK;
    info->user_dictionary_entries = dictionary.valid;
    if(!error) error = dictionary_error;
    info->error = error;
    if(explanation) furi_string_set(explanation, error ? "Library read failed" :
                                    info->truncated ? "Log scan limited to 1 MiB; counts incomplete" :
                                    (!info->system_dictionary_complete || !info->user_dictionary_complete) ?
                                    "Dictionary missing or scan limited to 1 MiB; counts incomplete" :
                                    "Read-only library summary; no keys displayed");
    return error == FSE_OK;
}

static void reader_wait_window(DiagReader* instance, bool sample_field) {
    while(!reader_cancelled(instance) && reader_elapsed(instance) < DIAG_READER_DURATION_MS) {
        if(sample_field) {
            ReaderEvent event = {
                .type = furi_hal_nfc_field_is_present() ? ReaderEventSampleOn : ReaderEventSampleOff,
                .elapsed_ms = reader_elapsed(instance)};
            furi_mutex_acquire(instance->mutex, FuriWaitForever);
            reader_process(&instance->core, &event);
            furi_mutex_release(instance->mutex);
        } else {
            reader_drain(instance);
        }
        furi_mutex_acquire(instance->mutex, FuriWaitForever);
        instance->core.stats.elapsed_ms = reader_elapsed(instance);
        furi_mutex_release(instance->mutex);
        furi_event_flag_wait(instance->events, READER_CANCEL, FuriFlagWaitAny | FuriFlagNoClear,
                             furi_ms_to_ticks(DIAG_READER_FIELD_SAMPLE_MS));
    }
}

static int32_t reader_worker(void* context) {
    DiagReader* instance = context;
    DiagReaderMode mode = instance->core.stats.mode;
    bool monitoring = false;
    bool hardware_error = false;
    if(mode == DiagReaderModeField) {
        FuriHalNfcError error = furi_hal_nfc_acquire();
        if(error != FuriHalNfcErrorNone) {
            reader_native_error(instance, "reader.hal.acquire", error);
            hardware_error = true;
        } else {
            error = furi_hal_nfc_field_detect_start();
            if(error != FuriHalNfcErrorNone) {
                reader_native_error(instance, "reader.field.start", error);
                hardware_error = true;
            } else {
                reader_wait_window(instance, true);
                monitoring = true;
                error = furi_hal_nfc_field_detect_stop();
                if(error != FuriHalNfcErrorNone) {
                    reader_native_error(instance, "reader.field.stop", error);
                    hardware_error = true;
                }
            }
            furi_hal_nfc_low_power_mode_start();
            furi_hal_nfc_release();
        }
    } else {
        FuriHalNfcError ready = furi_hal_nfc_is_hal_ready();
        if(ready != FuriHalNfcErrorNone) {
            reader_native_error(instance, "reader.hal.ready", ready);
            hardware_error = true;
        } else {
            /* The SDK has no checked nfc_alloc; normal loader app exclusivity
               is required across this readiness preflight and allocation. */
            Nfc* nfc = nfc_alloc();
            if(mode == DiagReaderModeTypeA) {
                nfc_set_fdt_listen_fc(nfc, ISO14443_3A_FDT_LISTEN_FC);
                nfc_config(nfc, NfcModeListener, NfcTechIso14443a);
                NfcError error = nfc_iso14443a_listener_set_col_res_data(
                    nfc, instance->identity.uid, (uint8_t)instance->identity.uid_size,
                    instance->identity.atqa, instance->identity.sak);
                if(error != NfcErrorNone) {
                    reader_native_error(instance, "reader.type_a.setup", error);
                    hardware_error = true;
                } else {
                    nfc_start(nfc, reader_type_a_callback, instance);
                    reader_wait_window(instance, false);
                    nfc_stop(nfc);
                    monitoring = true;
                }
            } else {
                MfClassicData* data = mf_classic_alloc();
                Iso14443_3aData* iso_a = data->iso14443_3a_data;
                memset(data, 0, sizeof(*data));
                memset(iso_a, 0, sizeof(*iso_a));
                data->iso14443_3a_data = iso_a;
                data->type = MfClassicType4k;
                iso14443_3a_set_uid(iso_a, instance->identity.uid, instance->identity.uid_size);
                iso14443_3a_set_atqa(iso_a, instance->identity.atqa);
                iso14443_3a_set_sak(iso_a, instance->identity.sak);
                instance->cuid = iso14443_3a_get_cuid(iso_a);
                NfcListener* listener = nfc_listener_alloc(nfc, NfcProtocolMfClassic, data);
                nfc_listener_start(listener, reader_classic_callback, instance);
                reader_wait_window(instance, false);
                nfc_listener_stop(listener);
                reader_drain(instance);
                nfc_listener_free(listener);
                mf_classic_free(data);
                monitoring = true;
            }
            reader_drain(instance);
            nfc_free(nfc);
        }
    }
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    instance->core.stats.elapsed_ms = reader_elapsed(instance);
    instance->core.stats.events_dropped = __atomic_load_n(&instance->queue_dropped, __ATOMIC_RELAXED);
    if(instance->core.field_known) {
        uint32_t duration = instance->core.stats.elapsed_ms - instance->core.stats.last_field_change_ms;
        if(instance->core.stats.field_present) instance->core.stats.field_on_ms += duration;
        else instance->core.stats.field_off_ms += duration;
    }
    instance->core.finished = true;
    if(instance->core.stats.events_dropped) {
        reader_log(&instance->core, DiagLogWarning, DiagStageProtocolRead,
                   "RF event queue overflow; some events lost; counters are incomplete");
    }
    furi_mutex_release(instance->mutex);

    /* NFC objects and HAL are no longer active before the storage append. */
    uint32_t saved = 0, already_saved = 0;
    int32_t storage_error = reader_append_pairs(instance->core.pairs, instance->core.pair_count,
                                               &saved, &already_saved);
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    instance->core.stats.pairs_saved = saved;
    instance->core.stats.pairs_already_saved = already_saved;
    instance->core.stats.storage_error = storage_error;
    if(saved) reader_log(&instance->core, DiagLogSuccess, DiagStageMetadataRead,
                         "Distinct matching transcript pairs appended to nfc/.mfkey32.log");
    if(already_saved) reader_log(&instance->core, DiagLogInfo, DiagStageMetadataRead,
                                 "Existing matching transcript pairs preserved; duplicates not appended");
    if(storage_error) {
        diag_model_set_error(&instance->core.model, storage_error < 0 ? "reader.log.limit" : "reader.log.append", storage_error);
        reader_log(&instance->core, DiagLogError, DiagStageMetadataRead,
                   "Nonce log append failed; existing bytes preserved; a new partial tail is possible");
    }
    bool cancelled = reader_cancelled(instance);
    if(cancelled) {
        diag_model_set_error(&instance->core.model, "reader.cancelled", 1);
        reader_log(&instance->core, DiagLogInfo, DiagStageNone,
                   "Reader run cancelled; listener stopped/joined; collected pairs handled safely");
    } else if(instance->core.stats.inconclusive) {
        reader_log(&instance->core, DiagLogWarning, DiagStageNone,
                   "Reader test inconclusive: unknown/protected/no matching interaction may be responsible");
    }
    bool observed = mode == DiagReaderModeField ? instance->core.stats.field_observed :
                    !instance->core.stats.inconclusive;
    instance->core.model.run_succeeded = monitoring && observed && !cancelled &&
                                        !hardware_error && !storage_error && !instance->core.stats.events_dropped;
    if(instance->core.model.run_succeeded) {
        diag_model_mark_stage_success(&instance->core.model, DiagStageComplete);
    }
    reader_log(&instance->core, DiagLogInfo, instance->core.model.last_successful_stage,
               "Reader run ended; no reader brand identified; recovery and card writing not performed here");
    instance->running = false;
    furi_mutex_release(instance->mutex);
    return 0;
}

DiagReader* diag_reader_alloc(void) {
    DiagReader* instance = calloc(1, sizeof(*instance));
    furi_check(instance);
    instance->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    instance->events = furi_event_flag_alloc();
    instance->queue = furi_message_queue_alloc(READER_QUEUE_SIZE, sizeof(ReaderEvent));
    instance->worker = furi_thread_alloc_ex("NfcReaderDiag", 4096, reader_worker, instance);
    reader_core_init(&instance->core, DiagReaderModeField);
    return instance;
}

void diag_reader_free(DiagReader* instance) {
    if(!instance) return;
    diag_reader_cancel(instance);
    if(instance->worker_started) furi_thread_join(instance->worker);
    furi_thread_free(instance->worker);
    furi_message_queue_free(instance->queue);
    furi_event_flag_free(instance->events);
    furi_mutex_free(instance->mutex);
    free(instance);
}

bool diag_reader_start(DiagReader* instance, DiagReaderMode mode, const DiagIsoAIdentity* identity) {
    if(!instance || mode > DiagReaderModeClassic) return false;
    if(identity && (!identity->present ||
       (identity->uid_size != 4 && identity->uid_size != 7 && identity->uid_size != 10))) return false;
    if(mode == DiagReaderModeClassic && identity && identity->uid_size == 10) return false;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    bool busy = instance->running;
    furi_mutex_release(instance->mutex);
    if(busy) return false;
    if(instance->worker_started) furi_thread_join(instance->worker);
    ReaderEvent discarded;
    while(furi_message_queue_get(instance->queue, &discarded, 0) == FuriStatusOk) {}
    furi_event_flag_clear(instance->events, READER_CANCEL);
    __atomic_store_n(&instance->queue_dropped, 0u, __ATOMIC_RELAXED);
    uint8_t random_uid[4] = {0};
    if(mode != DiagReaderModeField && !identity) furi_hal_random_fill_buf(random_uid, sizeof(random_uid));
    bool synthetic = false;
    if(!reader_configure_stimulus(mode, identity, random_uid, &instance->identity, &synthetic)) return false;
    DateTime rtc;
    furi_hal_rtc_get_datetime(&rtc);
    char timestamp[DIAG_TIMESTAMP_CAPACITY];
    snprintf(timestamp, sizeof(timestamp), "%04u-%02u-%02uT%02u:%02u:%02u",
             rtc.year, rtc.month, rtc.day, rtc.hour, rtc.minute, rtc.second);
    char runtime[DIAG_RUNTIME_VERSION_CAPACITY];
    snprintf(runtime, sizeof(runtime), "%.14s %.12s", version_get_version(NULL), version_get_githash(NULL));
    instance->started_tick = furi_get_tick();
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    reader_core_init(&instance->core, mode);
    instance->core.stats.synthetic_identity = synthetic;
    diag_model_set_timestamp(&instance->core.model, timestamp);
    diag_model_set_runtime_provenance(&instance->core.model, DIAG_FIRMWARE_BUILD, runtime);
    if(mode != DiagReaderModeField) {
        /* Configured listener UID is not an observed card or reader identity. */
        reader_log(&instance->core, DiagLogInfo, DiagStageNone,
                   identity ? "Synthetic RAM image advertises selected UID; no card blocks or keys copied" :
                   "Synthetic RAM image uses random diagnostic UID; no card data or keys copied");
    }
    reader_log(&instance->core, DiagLogInfo, DiagStageNone,
               mode == DiagReaderModeField ? "Passive field samples every 10ms; short pulses may be missed; no RF transmission" :
               mode == DiagReaderModeTypeA ? "Type A synthetic selection probe; request gaps are sampled, not RF latency" :
               "Classic full Nt/Nr/Ar only; SDK hides field/selection/RX totals; no universal recovery claim");
    instance->running = true;
    furi_mutex_release(instance->mutex);
    instance->worker_started = true;
    furi_thread_start(instance->worker);
    return true;
}

void diag_reader_cancel(DiagReader* instance) {
    if(instance) furi_event_flag_set(instance->events, READER_CANCEL);
}

bool diag_reader_is_running(DiagReader* instance) {
    if(!instance) return false;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    bool running = instance->running;
    furi_mutex_release(instance->mutex);
    return running;
}

void diag_reader_snapshot(DiagReader* instance, DiagModel* model, DiagReaderStats* stats) {
    if(!instance) return;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    reader_snapshot_core(&instance->core, model, stats);
    if(stats) stats->events_dropped = __atomic_load_n(&instance->queue_dropped, __ATOMIC_RELAXED);
    furi_mutex_release(instance->mutex);
}

void diag_reader_stimulus(DiagReader* instance, DiagIsoAIdentity* identity) {
    if(!instance || !identity) return;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    *identity = instance->identity;
    furi_mutex_release(instance->mutex);
}

bool diag_reader_read_model(
    DiagReader* instance, DiagModelReadCallback callback, void* context) {
    if(!instance || !callback) return false;
    furi_mutex_acquire(instance->mutex, FuriWaitForever);
    callback(&instance->core.model, context);
    furi_mutex_release(instance->mutex);
    return true;
}
#endif
