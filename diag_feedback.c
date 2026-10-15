#include "diag_feedback.h"
#include <stdio.h>

static const NotificationMessage tone_low = {
    .type = NotificationMessageTypeSoundOn,
    .data.sound = {.frequency = 1046.5f, .volume = 0.2f},
};
static const NotificationMessage tone_high = {
    .type = NotificationMessageTypeSoundOn,
    .data.sound = {.frequency = 1318.5f, .volume = 0.2f},
};
static const NotificationMessage sound_off = {.type = NotificationMessageTypeSoundOff};
static const NotificationMessage vibro_on = {
    .type = NotificationMessageTypeVibro, .data.vibro.on = true,
};
static const NotificationMessage vibro_off = {
    .type = NotificationMessageTypeVibro, .data.vibro.on = false,
};
static const NotificationMessage delay_20 = {
    .type = NotificationMessageTypeDelay, .data.delay.length = 20,
};
static const NotificationMessage delay_40 = {
    .type = NotificationMessageTypeDelay, .data.delay.length = 40,
};
static const NotificationMessage delay_50 = {
    .type = NotificationMessageTypeDelay, .data.delay.length = 50,
};
static const NotificationSequence success = {
    &vibro_on, &tone_low, &delay_50, &sound_off, &vibro_off,
    &delay_20, &tone_high, &delay_50, &sound_off, NULL,
};
static const NotificationSequence failure = {
    &vibro_on, &tone_high, &delay_50, &sound_off, &vibro_off,
    &delay_20, &tone_low, &delay_50, &sound_off, NULL,
};
static const NotificationSequence ready = {&vibro_on, &delay_40, &vibro_off, NULL};

void diag_feedback_success(NotificationApp* notification) {
    if(notification) notification_message(notification, &success);
}

void diag_feedback_failure(NotificationApp* notification) {
    if(notification) notification_message(notification, &failure);
}

void diag_feedback_ready(NotificationApp* notification) {
    if(notification) notification_message(notification, &ready);
}

bool diag_nonce_minimum_met(const DiagReaderStats* stats) {
    return stats && stats->mode == DiagReaderModeClassic && stats->nonce_pairs > 0;
}

bool diag_nonce_decode_ready(const DiagReaderStats* stats) {
    return stats && stats->mode == DiagReaderModeClassic && !stats->storage_error &&
        (stats->pairs_saved > 0 || stats->pairs_already_saved > 0);
}

DiagFeedbackResult diag_nonce_completion_feedback(
    const DiagReaderStats* stats,
    bool finish_capture,
    bool cancelled) {
    if(!stats || stats->mode != DiagReaderModeClassic || (!finish_capture && cancelled))
        return DiagFeedbackResultNone;
    if(diag_nonce_decode_ready(stats)) return DiagFeedbackResultSuccess;
    if(stats->storage_error) return DiagFeedbackResultFailure;
    return DiagFeedbackResultNone;
}

static void display_count(uint32_t value, char output[4]) {
    if(value > 99u) snprintf(output, 4, "99+");
    else snprintf(output, 4, "%lu", (unsigned long)value);
}

void diag_nonce_readiness_text(
    const DiagReaderStats* stats,
    bool active,
    char* output,
    size_t capacity) {
    if(!output || !capacity) return;
    output[0] = '\0';
    if(!stats || stats->mode != DiagReaderModeClassic) return;
    char pairs[4], reads[4];
    display_count(stats->nonce_pairs, pairs);
    display_count(stats->transcripts_collected, reads);
    const char* status = "Need matching reads";
    if(active && diag_nonce_minimum_met(stats)) status = "Pair ready; OK stops";
    else if(!active && stats->storage_error) status = "Save failed; see Log";
    else if(!active && diag_nonce_decode_ready(stats)) status = "Ready to decode";
    else if(!active && diag_nonce_minimum_met(stats)) status = "Pair not saved";
    snprintf(output, capacity, "Pairs:%s/1 Reads:%s\n%s\nGoal: each needed key", pairs, reads, status);
}

const char* diag_nonce_readiness_detail(void) {
    return "Minimum: 1 pair = 2 distinct complete contexts, same UID/sector/key. "
           "Goal: each needed key; count depends on card. "
           "Collection does not prove key recovery or reader acceptance.";
}
