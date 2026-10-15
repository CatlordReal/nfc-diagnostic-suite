#include "../diag_feedback.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned calls;
static const NotificationSequence* sent;
void notification_message(NotificationApp* app, const NotificationSequence* sequence) {
    assert(app);
    ++calls;
    sent = sequence;
}
static void sequence(bool ascending, bool ready_only) {
    unsigned notes = 0, pulses = 0, delay = 0;
    float previous = 0;
    bool vibration = false, sound = false;
    for(size_t index = 0; (*sent)[index]; ++index) {
        assert(index < 12u);
        const NotificationMessage* message = (*sent)[index];
        switch(message->type) {
        case NotificationMessageTypeSoundOn:
            assert(!ready_only && message->data.sound.volume == 0.2f);
            if(notes) assert(ascending ? message->data.sound.frequency > previous :
                                          message->data.sound.frequency < previous);
            previous = message->data.sound.frequency;
            ++notes; sound = true; break;
        case NotificationMessageTypeSoundOff: sound = false; break;
        case NotificationMessageTypeVibro:
            vibration = message->data.vibro.on;
            if(vibration) ++pulses;
            break;
        case NotificationMessageTypeDelay: delay += message->data.delay.length; break;
        default: assert(!"Unexpected message or user-setting override");
        }
    }
    assert(!sound && !vibration && pulses == 1u);
    assert(notes == (ready_only ? 0u : 2u));
    assert(delay == (ready_only ? 40u : 120u));
}
static void text(const DiagReaderStats* stats, bool active, const char* expected) {
    char output[96];
    diag_nonce_readiness_text(stats, active, output, sizeof(output));
    assert(strstr(output, expected));
    size_t width = 0, lines = 1;
    for(const char* cursor = output; *cursor; ++cursor) {
        if(*cursor == '\n') {assert(width <= 21u); width = 0; ++lines;}
        else ++width;
    }
    assert(lines == 3u && width <= 21u);
}
int main(void) {
    NotificationApp* notification = (NotificationApp*)&calls;
    diag_feedback_success(NULL); diag_feedback_failure(NULL); diag_feedback_ready(NULL);
    assert(!calls);
    diag_feedback_success(notification); sequence(true, false);
    diag_feedback_failure(notification); sequence(false, false);
    diag_feedback_ready(notification); sequence(false, true);
    assert(calls == 3u);
    DiagReaderStats stats = {.mode = DiagReaderModeClassic};
    assert(diag_nonce_completion_feedback(NULL, false, false) == DiagFeedbackResultNone);
    assert(diag_nonce_completion_feedback(&stats, false, false) == DiagFeedbackResultNone);
    assert(diag_nonce_completion_feedback(&stats, true, true) == DiagFeedbackResultNone);
    assert(diag_nonce_completion_feedback(&stats, false, true) == DiagFeedbackResultNone);
    assert(!diag_nonce_minimum_met(NULL) && !diag_nonce_decode_ready(NULL));
    assert(!diag_nonce_minimum_met(&stats) && !diag_nonce_decode_ready(&stats));
    text(&stats, true, "Need matching reads");
    stats.transcripts_collected = 1;
    text(&stats, true, "Pairs:0/1 Reads:1");
    stats.transcripts_collected = 2; stats.nonce_pairs = 1;
    assert(diag_nonce_minimum_met(&stats) && !diag_nonce_decode_ready(&stats));
    text(&stats, true, "Pair ready; OK stops");
    text(&stats, false, "Pair not saved");
    stats.pairs_saved = 1;
    assert(diag_nonce_decode_ready(&stats));
    assert(diag_nonce_completion_feedback(&stats, false, false) == DiagFeedbackResultSuccess);
    assert(diag_nonce_completion_feedback(&stats, true, true) == DiagFeedbackResultSuccess);
    assert(diag_nonce_completion_feedback(&stats, false, true) == DiagFeedbackResultNone);
    text(&stats, false, "Ready to decode");
    stats.pairs_saved = 0; stats.pairs_already_saved = 1;
    assert(diag_nonce_decode_ready(&stats));
    stats.storage_error = 7;
    assert(!diag_nonce_decode_ready(&stats));
    assert(diag_nonce_completion_feedback(&stats, false, false) == DiagFeedbackResultFailure);
    assert(diag_nonce_completion_feedback(&stats, true, true) == DiagFeedbackResultFailure);
    assert(diag_nonce_completion_feedback(&stats, false, true) == DiagFeedbackResultNone);
    text(&stats, false, "Save failed; see Log");
    stats.nonce_pairs = UINT32_MAX; stats.transcripts_collected = UINT32_MAX;
    text(&stats, true, "Pairs:99+/1 Reads:99+");
    char small[4] = {0};
    diag_nonce_readiness_text(&stats, true, small, sizeof(small));
    assert(small[3] == '\0');
    diag_nonce_readiness_text(&stats, true, NULL, 1);
    diag_nonce_readiness_text(&stats, true, small, 0);
    diag_nonce_readiness_text(NULL, true, small, sizeof(small)); assert(!*small);
    stats.mode = DiagReaderModeField;
    assert(!diag_nonce_minimum_met(&stats) && !diag_nonce_decode_ready(&stats));
    assert(diag_nonce_completion_feedback(&stats, false, false) == DiagFeedbackResultNone);
    stats.mode = DiagReaderModeTypeA;
    assert(diag_nonce_completion_feedback(&stats, true, true) == DiagFeedbackResultNone);
    stats.mode = DiagReaderModeField;
    small[0] = 'x'; diag_nonce_readiness_text(&stats, true, small, sizeof(small)); assert(!*small);
    assert(strstr(diag_nonce_readiness_detail(), "2 distinct complete contexts"));
    assert(strstr(diag_nonce_readiness_detail(), "same UID/sector/key"));
    puts("Feedback sequences and nonce readiness checks passed");
}
