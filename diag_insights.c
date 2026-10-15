#include "diag_insights.h"

#include <limits.h>
#include <string.h>

#define DIAG_FINGERPRINT_VALID_FLAGS ((uint8_t)0x7Fu)
#define DIAG_FINGERPRINT_CRC_OFFSET 66u

static uint16_t diag_u16_saturate(uint32_t value) {
    return value > UINT16_MAX ? UINT16_MAX : (uint16_t)value;
}

static uint32_t diag_u32_add_saturate(uint32_t left, uint32_t right) {
    return UINT32_MAX - left < right ? UINT32_MAX : left + right;
}

static uint16_t diag_rate_per_min(uint32_t count, uint32_t elapsed_ms) {
    if(!elapsed_ms || !count) return 0u;
    uint64_t rate = ((uint64_t)count * 60000u + elapsed_ms / 2u) / elapsed_ms;
    return rate > UINT16_MAX ? UINT16_MAX : (uint16_t)rate;
}

static uint16_t diag_duty_permille(uint32_t present, uint32_t absent) {
    uint64_t total = (uint64_t)present + absent;
    if(!total) return 0u;
    return (uint16_t)(((uint64_t)present * 1000u + total / 2u) / total);
}

static bool diag_stimulus_valid(const DiagIsoAIdentity* identity) {
    if(!identity || !identity->present) return false;
    if(identity->uid_size != 4u && identity->uid_size != 7u && identity->uid_size != 10u) {
        return false;
    }
    return identity->cascade_count ==
           (identity->uid_size == 4u ? 1u : identity->uid_size == 7u ? 2u : 3u);
}

bool diag_reader_fingerprint_from_reader(
    const DiagReaderStats* stats,
    const DiagIsoAIdentity* optional_stimulus,
    DiagReaderFingerprint* fingerprint) {
    if(!stats || !fingerprint || (unsigned)stats->mode > DiagReaderModeClassic) return false;
    if(optional_stimulus && !diag_stimulus_valid(optional_stimulus)) return false;
    if(stats->mode == DiagReaderModeField && optional_stimulus) return false;

    memset(fingerprint, 0, sizeof(*fingerprint));
    fingerprint->version = DIAG_READER_FINGERPRINT_VERSION;
    fingerprint->kind = DiagReaderFingerprintKindNfc;
    fingerprint->mode = (uint8_t)stats->mode;
    fingerprint->elapsed_ms = stats->elapsed_ms;
    fingerprint->sample_period_ms = diag_u16_saturate(stats->sample_period_ms);
    fingerprint->sample_count = diag_u16_saturate(stats->samples);

    if(stats->field_available) {
        fingerprint->flags |= DiagReaderFingerprintHasField;
        fingerprint->field_duty_permille =
            diag_duty_permille(stats->field_on_ms, stats->field_off_ms);
        fingerprint->field_edge_rate_per_min = diag_rate_per_min(
            diag_u32_add_saturate(stats->field_on_count, stats->field_off_count),
            stats->elapsed_ms);
    }
    if(stats->selection_available) {
        fingerprint->flags |= DiagReaderFingerprintHasSelection;
        fingerprint->selection_rate_per_min =
            diag_rate_per_min(stats->selection_count, stats->elapsed_ms);
    }
    if(stats->rx_total_available || stats->mode == DiagReaderModeClassic) {
        fingerprint->flags |= DiagReaderFingerprintHasTraffic;
        fingerprint->request_rate_per_min =
            diag_rate_per_min(stats->request_count, stats->elapsed_ms);
        fingerprint->auth_rate_per_min =
            diag_rate_per_min(stats->auth_request_count, stats->elapsed_ms);
        fingerprint->error_rate_per_min =
            diag_rate_per_min(
                diag_u32_add_saturate(stats->error_count, stats->events_dropped),
                stats->elapsed_ms);
        fingerprint->min_request_gap_ms = diag_u16_saturate(stats->min_request_gap_ms);
        fingerprint->max_request_gap_ms = diag_u16_saturate(stats->max_request_gap_ms);
    }
    if(optional_stimulus) {
        fingerprint->flags |= DiagReaderFingerprintHasStimulus;
        fingerprint->stimulus_uid_size = (uint8_t)optional_stimulus->uid_size;
        memcpy(
            fingerprint->stimulus_uid,
            optional_stimulus->uid,
            optional_stimulus->uid_size);
        memcpy(fingerprint->stimulus_atqa, optional_stimulus->atqa, 2u);
        fingerprint->stimulus_sak = optional_stimulus->sak;
    }
    if(stats->synthetic_identity) {
        fingerprint->flags |= DiagReaderFingerprintSyntheticStimulus;
    }

    uint32_t evidence =
        diag_u32_add_saturate(stats->field_on_count, stats->field_off_count);
    if(stats->mode == DiagReaderModeTypeA) {
        evidence = diag_u32_add_saturate(stats->selection_count, stats->request_count);
    } else if(stats->mode == DiagReaderModeClassic) {
        evidence = diag_u32_add_saturate(stats->auth_request_count, stats->auth_full_count);
    }
    fingerprint->evidence_count = diag_u16_saturate(evidence);
    return true;
}

bool diag_reader_fingerprint_from_fields(
    const DiagLfStats* stats,
    DiagReaderFingerprint* fingerprint) {
    if(!stats || !fingerprint ||
       (stats->mode != DiagLfModeReader && stats->mode != DiagLfModeReaderBoth)) {
        return false;
    }
    memset(fingerprint, 0, sizeof(*fingerprint));
    fingerprint->version = DIAG_READER_FINGERPRINT_VERSION;
    fingerprint->kind = DiagReaderFingerprintKindLfFields;
    fingerprint->mode = (uint8_t)stats->mode;
    fingerprint->elapsed_ms = stats->elapsed_ms;
    fingerprint->sample_period_ms = diag_u16_saturate(stats->sample_period_ms);
    fingerprint->sample_count = diag_u16_saturate(stats->samples_total);
    fingerprint->evidence_count = diag_u16_saturate(stats->field_present_samples);
    fingerprint->flags |= DiagReaderFingerprintHasField;
    fingerprint->field_duty_permille = diag_duty_permille(
        stats->field_present_samples, stats->field_absent_samples);
    if(stats->mode == DiagLfModeReaderBoth) {
        fingerprint->flags |= DiagReaderFingerprintHasNfcField;
        fingerprint->nfc_field_duty_permille = diag_duty_permille(
            stats->nfc_field_present_samples, stats->nfc_field_absent_samples);
    }
    if(stats->field_present_samples && stats->frequency_hz_min &&
       stats->frequency_hz_max >= stats->frequency_hz_min) {
        fingerprint->flags |= DiagReaderFingerprintHasFrequency;
        fingerprint->frequency_hz_min = stats->frequency_hz_min;
        fingerprint->frequency_hz_max = stats->frequency_hz_max;
        fingerprint->frequency_hz_last = stats->frequency_hz_last;
    }
    return true;
}

static bool diag_fingerprint_valid(const DiagReaderFingerprint* fingerprint) {
    if(!fingerprint || fingerprint->version != DIAG_READER_FINGERPRINT_VERSION ||
       (fingerprint->flags & (uint8_t)~DIAG_FINGERPRINT_VALID_FLAGS) ||
       fingerprint->field_duty_permille > 1000u ||
       fingerprint->nfc_field_duty_permille > 1000u) {
        return false;
    }
    const bool stimulus =
        (fingerprint->flags & DiagReaderFingerprintHasStimulus) != 0u;
    if(stimulus) {
        if(fingerprint->stimulus_uid_size != 4u && fingerprint->stimulus_uid_size != 7u &&
           fingerprint->stimulus_uid_size != 10u) {
            return false;
        }
    } else {
        if(fingerprint->stimulus_uid_size || fingerprint->stimulus_atqa[0] ||
           fingerprint->stimulus_atqa[1] || fingerprint->stimulus_sak) {
            return false;
        }
        for(size_t index = 0; index < sizeof(fingerprint->stimulus_uid); ++index) {
            if(fingerprint->stimulus_uid[index]) return false;
        }
    }
    if(fingerprint->stimulus_uid_size < sizeof(fingerprint->stimulus_uid)) {
        for(size_t index = fingerprint->stimulus_uid_size;
            index < sizeof(fingerprint->stimulus_uid);
            ++index) {
            if(fingerprint->stimulus_uid[index]) return false;
        }
    }

    if(fingerprint->kind == DiagReaderFingerprintKindNfc) {
        if(fingerprint->mode > DiagReaderModeClassic) return false;
        if(fingerprint->mode == DiagReaderModeField &&
           (stimulus ||
            (fingerprint->flags &
             (DiagReaderFingerprintHasSelection |
              DiagReaderFingerprintHasTraffic |
              DiagReaderFingerprintSyntheticStimulus)))) {
            return false;
        }
        if(fingerprint->flags & (DiagReaderFingerprintHasNfcField |
                                 DiagReaderFingerprintHasFrequency)) {
            return false;
        }
    } else if(fingerprint->kind == DiagReaderFingerprintKindLfFields) {
        if(fingerprint->mode != DiagLfModeReader &&
           fingerprint->mode != DiagLfModeReaderBoth) {
            return false;
        }
        if(!(fingerprint->flags & DiagReaderFingerprintHasField) || stimulus ||
           (fingerprint->flags &
                        (DiagReaderFingerprintHasSelection |
                         DiagReaderFingerprintHasTraffic |
                         DiagReaderFingerprintSyntheticStimulus))) {
            return false;
        }
        if(fingerprint->mode == DiagLfModeReader &&
           (fingerprint->flags & DiagReaderFingerprintHasNfcField)) {
            return false;
        }
    } else {
        return false;
    }

    if(!(fingerprint->flags & DiagReaderFingerprintHasField) &&
       (fingerprint->field_duty_permille || fingerprint->field_edge_rate_per_min)) {
        return false;
    }
    if(!(fingerprint->flags & DiagReaderFingerprintHasNfcField) &&
       fingerprint->nfc_field_duty_permille) {
        return false;
    }
    if(!(fingerprint->flags & DiagReaderFingerprintHasSelection) &&
       fingerprint->selection_rate_per_min) {
        return false;
    }
    if(!(fingerprint->flags & DiagReaderFingerprintHasTraffic) &&
       (fingerprint->request_rate_per_min || fingerprint->auth_rate_per_min ||
        fingerprint->error_rate_per_min || fingerprint->min_request_gap_ms ||
        fingerprint->max_request_gap_ms)) {
        return false;
    }
    if(!(fingerprint->flags & DiagReaderFingerprintHasFrequency)) {
        if(fingerprint->frequency_hz_min || fingerprint->frequency_hz_max ||
           fingerprint->frequency_hz_last) {
            return false;
        }
    } else if(!fingerprint->frequency_hz_min ||
              fingerprint->frequency_hz_max < fingerprint->frequency_hz_min ||
              (fingerprint->frequency_hz_last &&
               (fingerprint->frequency_hz_last < fingerprint->frequency_hz_min ||
                fingerprint->frequency_hz_last > fingerprint->frequency_hz_max))) {
        return false;
    }
    return fingerprint->min_request_gap_ms <= fingerprint->max_request_gap_ms;
}

static uint32_t diag_crc32(const uint8_t* data, size_t size) {
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    for(size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for(unsigned bit = 0; bit < 8u; ++bit) {
            crc = (crc >> 1u) ^
                  (UINT32_C(0xEDB88320) & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return ~crc;
}

static void diag_put_u16(uint8_t* output, size_t* position, uint16_t value) {
    output[(*position)++] = (uint8_t)value;
    output[(*position)++] = (uint8_t)(value >> 8u);
}

static void diag_put_u32(uint8_t* output, size_t* position, uint32_t value) {
    for(unsigned shift = 0; shift < 32u; shift += 8u) {
        output[(*position)++] = (uint8_t)(value >> shift);
    }
}

static uint16_t diag_get_u16(const uint8_t* data, size_t* position) {
    uint16_t value = data[*position] | (uint16_t)((uint16_t)data[*position + 1u] << 8u);
    *position += 2u;
    return value;
}

static uint32_t diag_get_u32(const uint8_t* data, size_t* position) {
    uint32_t value = 0u;
    for(unsigned shift = 0; shift < 32u; shift += 8u) {
        value |= (uint32_t)data[(*position)++] << shift;
    }
    return value;
}

size_t diag_reader_fingerprint_encode(
    const DiagReaderFingerprint* fingerprint,
    uint8_t* output,
    size_t capacity) {
    if(!diag_fingerprint_valid(fingerprint) || !output ||
       capacity < DIAG_READER_FINGERPRINT_ENCODED_SIZE) {
        return 0u;
    }
    size_t position = 0u;
    memcpy(output + position, "RDFP", 4u);
    position += 4u;
    output[position++] = DIAG_READER_FINGERPRINT_VERSION;
    output[position++] = DIAG_READER_FINGERPRINT_ENCODED_SIZE;
    output[position++] = 0u;
    output[position++] = 0u;
    output[position++] = fingerprint->kind;
    output[position++] = fingerprint->mode;
    output[position++] = fingerprint->flags;
    output[position++] = fingerprint->stimulus_uid_size;
    memcpy(output + position, fingerprint->stimulus_uid, DIAG_MAX_ISO_A_UID_BYTES);
    position += DIAG_MAX_ISO_A_UID_BYTES;
    memcpy(output + position, fingerprint->stimulus_atqa, 2u);
    position += 2u;
    output[position++] = fingerprint->stimulus_sak;
    output[position++] = 0u;

#define DIAG_PUT_FIELD(field) diag_put_u16(output, &position, fingerprint->field)
    DIAG_PUT_FIELD(sample_period_ms);
    DIAG_PUT_FIELD(field_duty_permille);
    DIAG_PUT_FIELD(nfc_field_duty_permille);
    DIAG_PUT_FIELD(field_edge_rate_per_min);
    DIAG_PUT_FIELD(selection_rate_per_min);
    DIAG_PUT_FIELD(request_rate_per_min);
    DIAG_PUT_FIELD(auth_rate_per_min);
    DIAG_PUT_FIELD(error_rate_per_min);
    DIAG_PUT_FIELD(min_request_gap_ms);
    DIAG_PUT_FIELD(max_request_gap_ms);
    DIAG_PUT_FIELD(sample_count);
    DIAG_PUT_FIELD(evidence_count);
#undef DIAG_PUT_FIELD
    diag_put_u32(output, &position, fingerprint->elapsed_ms);
    diag_put_u32(output, &position, fingerprint->frequency_hz_min);
    diag_put_u32(output, &position, fingerprint->frequency_hz_max);
    diag_put_u32(output, &position, fingerprint->frequency_hz_last);
    if(position != DIAG_FINGERPRINT_CRC_OFFSET) return 0u;
    diag_put_u32(output, &position, diag_crc32(output, position));
    return position == DIAG_READER_FINGERPRINT_ENCODED_SIZE ? position : 0u;
}

bool diag_reader_fingerprint_decode(
    const uint8_t* data,
    size_t size,
    DiagReaderFingerprint* fingerprint) {
    if(!data || !fingerprint || size != DIAG_READER_FINGERPRINT_ENCODED_SIZE ||
       memcmp(data, "RDFP", 4u) || data[4] != DIAG_READER_FINGERPRINT_VERSION ||
       data[5] != DIAG_READER_FINGERPRINT_ENCODED_SIZE || data[6] || data[7]) {
        return false;
    }
    size_t crc_position = DIAG_FINGERPRINT_CRC_OFFSET;
    if(diag_get_u32(data, &crc_position) != diag_crc32(data, DIAG_FINGERPRINT_CRC_OFFSET)) {
        return false;
    }
    DiagReaderFingerprint decoded;
    memset(&decoded, 0, sizeof(decoded));
    decoded.version = data[4];
    size_t position = 8u;
    decoded.kind = data[position++];
    decoded.mode = data[position++];
    decoded.flags = data[position++];
    decoded.stimulus_uid_size = data[position++];
    memcpy(decoded.stimulus_uid, data + position, DIAG_MAX_ISO_A_UID_BYTES);
    position += DIAG_MAX_ISO_A_UID_BYTES;
    memcpy(decoded.stimulus_atqa, data + position, 2u);
    position += 2u;
    decoded.stimulus_sak = data[position++];
    if(data[position++]) return false;

#define DIAG_GET_FIELD(field) decoded.field = diag_get_u16(data, &position)
    DIAG_GET_FIELD(sample_period_ms);
    DIAG_GET_FIELD(field_duty_permille);
    DIAG_GET_FIELD(nfc_field_duty_permille);
    DIAG_GET_FIELD(field_edge_rate_per_min);
    DIAG_GET_FIELD(selection_rate_per_min);
    DIAG_GET_FIELD(request_rate_per_min);
    DIAG_GET_FIELD(auth_rate_per_min);
    DIAG_GET_FIELD(error_rate_per_min);
    DIAG_GET_FIELD(min_request_gap_ms);
    DIAG_GET_FIELD(max_request_gap_ms);
    DIAG_GET_FIELD(sample_count);
    DIAG_GET_FIELD(evidence_count);
#undef DIAG_GET_FIELD
    decoded.elapsed_ms = diag_get_u32(data, &position);
    decoded.frequency_hz_min = diag_get_u32(data, &position);
    decoded.frequency_hz_max = diag_get_u32(data, &position);
    decoded.frequency_hz_last = diag_get_u32(data, &position);
    if(position != DIAG_FINGERPRINT_CRC_OFFSET || !diag_fingerprint_valid(&decoded)) {
        return false;
    }
    *fingerprint = decoded;
    return true;
}

static bool diag_same_stimulus(
    const DiagReaderFingerprint* left,
    const DiagReaderFingerprint* right) {
    return left->stimulus_uid_size == right->stimulus_uid_size &&
           left->stimulus_sak == right->stimulus_sak &&
           !memcmp(left->stimulus_atqa, right->stimulus_atqa, 2u) &&
           !memcmp(left->stimulus_uid, right->stimulus_uid, left->stimulus_uid_size);
}

static bool diag_fingerprint_sufficient(const DiagReaderFingerprint* fingerprint) {
    if(fingerprint->elapsed_ms < 100u) return false;
    if(fingerprint->kind == DiagReaderFingerprintKindLfFields) {
        return fingerprint->elapsed_ms >= 1000u && fingerprint->sample_count >= 10u &&
               fingerprint->evidence_count >= 3u &&
               (fingerprint->flags & DiagReaderFingerprintHasFrequency);
    }
    if(fingerprint->mode == DiagReaderModeField) {
        return fingerprint->elapsed_ms >= 1000u && fingerprint->sample_count >= 20u &&
               fingerprint->evidence_count >= 2u &&
               (fingerprint->flags & DiagReaderFingerprintHasField);
    }
    return fingerprint->evidence_count >= (fingerprint->mode == DiagReaderModeClassic ? 2u : 3u) &&
           (fingerprint->flags & DiagReaderFingerprintHasTraffic) &&
           (fingerprint->flags & DiagReaderFingerprintHasStimulus);
}

static unsigned diag_relative_similarity(uint32_t left, uint32_t right) {
    if(left == right) return 100u;
    uint32_t largest = left > right ? left : right;
    if(!largest) return 100u;
    uint64_t percent = ((uint64_t)(left > right ? left - right : right - left) * 100u) /
                       largest;
    uint64_t penalty = percent * 2u;
    return penalty >= 100u ? 0u : (unsigned)(100u - penalty);
}

static unsigned diag_duty_similarity(uint16_t left, uint16_t right) {
    unsigned difference = left > right ? left - right : right - left;
    unsigned penalty = difference / 5u;
    return penalty >= 100u ? 0u : 100u - penalty;
}

static unsigned diag_frequency_similarity(uint32_t left, uint32_t right) {
    if(left == right) return 100u;
    uint32_t largest = left > right ? left : right;
    if(!largest) return 100u;
    uint64_t percent = ((uint64_t)(left > right ? left - right : right - left) * 100u) /
                       largest;
    uint64_t penalty = percent * 8u;
    return penalty >= 100u ? 0u : (unsigned)(100u - penalty);
}

static void diag_add_score(
    uint32_t* total,
    uint32_t* weight_total,
    unsigned similarity,
    unsigned weight) {
    *total += similarity * weight;
    *weight_total += weight;
}

DiagReaderFingerprintMatch diag_reader_fingerprint_compare(
    const DiagReaderFingerprint* left,
    const DiagReaderFingerprint* right) {
    DiagReaderFingerprintMatch match = {
        .result = DiagReaderFingerprintInvalid,
        .reason = "Invalid profile",
    };
    if(!diag_fingerprint_valid(left) || !diag_fingerprint_valid(right)) return match;
    if(left->kind != right->kind || left->mode != right->mode) {
        match.result = DiagReaderFingerprintNotComparable;
        match.reason = "Probe modes differ";
        return match;
    }
    const uint8_t availability_mask =
        DiagReaderFingerprintHasField | DiagReaderFingerprintHasNfcField |
        DiagReaderFingerprintHasSelection | DiagReaderFingerprintHasTraffic;
    if((left->flags & availability_mask) != (right->flags & availability_mask) ||
       left->sample_period_ms != right->sample_period_ms) {
        match.result = DiagReaderFingerprintNotComparable;
        match.reason = "Metric availability differs";
        return match;
    }
    if(left->kind == DiagReaderFingerprintKindNfc &&
       left->mode != DiagReaderModeField) {
        if(!(left->flags & DiagReaderFingerprintHasStimulus) ||
           !(right->flags & DiagReaderFingerprintHasStimulus)) {
            match.result = DiagReaderFingerprintInsufficient;
            match.reason = "Stimulus context missing";
            return match;
        }
        if(!diag_same_stimulus(left, right) ||
           ((left->flags ^ right->flags) & DiagReaderFingerprintSyntheticStimulus)) {
            match.result = DiagReaderFingerprintNotComparable;
            match.reason = "Stimulus context differs";
            return match;
        }
    }
    if(!diag_fingerprint_sufficient(left) || !diag_fingerprint_sufficient(right)) {
        match.result = DiagReaderFingerprintInsufficient;
        match.reason = "Too little evidence";
        return match;
    }

    uint32_t total = 0u;
    uint32_t weights = 0u;
    if(left->flags & DiagReaderFingerprintHasField) {
        diag_add_score(&total, &weights,
            diag_duty_similarity(left->field_duty_permille, right->field_duty_permille), 2u);
        if(left->kind == DiagReaderFingerprintKindNfc) {
            diag_add_score(&total, &weights, diag_relative_similarity(
                left->field_edge_rate_per_min, right->field_edge_rate_per_min), 2u);
        }
    }
    if(left->flags & DiagReaderFingerprintHasNfcField) {
        diag_add_score(&total, &weights, diag_duty_similarity(
            left->nfc_field_duty_permille, right->nfc_field_duty_permille), 1u);
    }
    if(left->flags & DiagReaderFingerprintHasSelection) {
        diag_add_score(&total, &weights, diag_relative_similarity(
            left->selection_rate_per_min, right->selection_rate_per_min), 1u);
    }
    if(left->flags & DiagReaderFingerprintHasTraffic) {
        diag_add_score(&total, &weights, diag_relative_similarity(
            left->request_rate_per_min, right->request_rate_per_min), 3u);
        diag_add_score(&total, &weights, diag_relative_similarity(
            left->auth_rate_per_min, right->auth_rate_per_min), 2u);
        diag_add_score(&total, &weights, diag_relative_similarity(
            left->error_rate_per_min, right->error_rate_per_min), 1u);
        if(left->min_request_gap_ms || right->min_request_gap_ms) {
            diag_add_score(&total, &weights, diag_relative_similarity(
                left->min_request_gap_ms, right->min_request_gap_ms), 2u);
        }
        if(left->max_request_gap_ms || right->max_request_gap_ms) {
            diag_add_score(&total, &weights, diag_relative_similarity(
                left->max_request_gap_ms, right->max_request_gap_ms), 2u);
        }
    }
    if(left->kind == DiagReaderFingerprintKindLfFields) {
        diag_add_score(&total, &weights, diag_frequency_similarity(
            left->frequency_hz_min, right->frequency_hz_min), 3u);
        diag_add_score(&total, &weights, diag_frequency_similarity(
            left->frequency_hz_max, right->frequency_hz_max), 3u);
    }
    match.score = weights ? (uint8_t)(total / weights) : 0u;
    match.result = match.score >= 70u ? DiagReaderFingerprintSimilar :
                                       DiagReaderFingerprintDifferent;
    match.reason = match.result == DiagReaderFingerprintSimilar ?
        "Similar timing/rates; identity not proven" : "Timing/rates differ";
    return match;
}

static bool diag_recommendation(
    DiagInsightRecommendation* recommendation,
    const char* cause,
    const char* next_test) {
    recommendation->cause = cause;
    recommendation->next_test = next_test;
    return true;
}

bool diag_insights_recommend(
    const DiagModel* model,
    const DiagReaderStats* reader,
    const DiagLfStats* fields,
    DiagInsightRecommendation* recommendation) {
    if(!recommendation || (!model && !reader && !fields)) return false;
    recommendation->cause = NULL;
    recommendation->next_test = NULL;

    if(model && model->error.present && !strcmp(model->error.domain, "app.cancelled")) {
        return diag_recommendation(
            recommendation, "Test cancelled.", "Retry without moving the card.");
    }
    if(model && model->error.present) {
        return diag_recommendation(
            recommendation, "Recorded error.", "Review exact error; retry once.");
    }
    if(reader) {
        if(reader->events_dropped || reader->error_count) {
            return diag_recommendation(
                recommendation, "Reader events dropped.", "Retry; compare a complete run.");
        }
        if(reader->mode == DiagReaderModeClassic) {
            if(reader->nonce_pairs) {
                return diag_recommendation(
                    recommendation, "Complete Classic pair available.",
                    "Coverage depends on sector and key type.");
            }
            if(reader->transcripts_collected) {
                return diag_recommendation(
                    recommendation, "No distinct Classic pair.",
                    "Hold Flipper to reader again.");
            }
            return diag_recommendation(
                recommendation, "No complete Classic pair.", "Retry reader test with same UID.");
        }
        if(reader->mode == DiagReaderModeTypeA &&
           !reader->selection_count && !reader->request_count) {
            return diag_recommendation(
                recommendation, "No Type A request.", "Retry passive field, then LF.");
        }
        if(reader->mode == DiagReaderModeField && !reader->field_observed) {
            return diag_recommendation(
                recommendation, "No NFC field sampled.", "Reposition; test LF.");
        }
    }
    if(fields) {
        if(fields->cancelled) {
            return diag_recommendation(
                recommendation, "Test cancelled.", "Retry without moving the card.");
        }
        if(fields->mode != DiagLfModeCard &&
           !fields->field_seen && !fields->nfc_field_seen) {
            return diag_recommendation(
                recommendation, "No reader field sampled.",
                "Reposition; repeat.");
        }
        if(fields->mode != DiagLfModeCard && fields->field_seen &&
           !fields->frequency_hz_min) {
            return diag_recommendation(
                recommendation, "LF frequency unavailable.", "Retry; result inconclusive.");
        }
        if(fields->mode == DiagLfModeCard && !fields->decoded) {
            return diag_recommendation(
                recommendation, "No LF protocol decoded.", "Reposition; retry; test NFC.");
        }
    }
    if(model && !model->run_succeeded) {
        if(model->last_successful_stage == DiagStageNone) {
            return diag_recommendation(
                recommendation, "No supported response.", "Reposition; retry other band.");
        }
        return diag_recommendation(
            recommendation, "Observation incomplete.", "Retry with unchanged setup.");
    }
    return diag_recommendation(
        recommendation, "No specific failure.", "Compare a complete same-context run.");
}
