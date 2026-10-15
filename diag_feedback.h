#ifndef DIAG_FEEDBACK_H
#define DIAG_FEEDBACK_H

#include "diag_reader.h"
#include <notification/notification.h>

/* The caller owns the notification record and gates each real outcome once.
   These asynchronous sequences respect native sound/vibration/stealth settings. */
void diag_feedback_success(NotificationApp* notification);
void diag_feedback_failure(NotificationApp* notification);
/* A short vibration for the first usable pair, not a recovery-success signal. */
void diag_feedback_ready(NotificationApp* notification);

bool diag_nonce_minimum_met(const DiagReaderStats* stats);
/* Requires at least one synced/existing pair and no append error. */
bool diag_nonce_decode_ready(const DiagReaderStats* stats);
typedef enum {
    DiagFeedbackResultNone = 0,
    DiagFeedbackResultSuccess,
    DiagFeedbackResultFailure,
} DiagFeedbackResult;
/* Natural timeout and explicit Done may report a durable result. Back/cancel stays silent. */
DiagFeedbackResult diag_nonce_completion_feedback(
    const DiagReaderStats* stats,
    bool finish_capture,
    bool cancelled);
/* Three lines, at most 21 columns each; use ArtNone. Display counts cap at 99+.
   Capture remains stoppable before the minimum. Readiness is not key recovery. */
void diag_nonce_readiness_text(
    const DiagReaderStats* stats,
    bool active,
    char* output,
    size_t capacity);
const char* diag_nonce_readiness_detail(void);

#endif
