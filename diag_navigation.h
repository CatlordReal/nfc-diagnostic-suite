#ifndef DIAG_NAVIGATION_H
#define DIAG_NAVIGATION_H

#include <stdbool.h>
#include <stddef.h>

#define DIAG_NAV_HISTORY_CAPACITY 16u

typedef enum {
    DiagNavHome = 0,
    DiagNavReader,
    DiagNavWorkflowStart,
    DiagNavWorkflow,
    DiagNavSaved,
    DiagNavSessions,
    DiagNavWorkflowTools,
    DiagNavActiveScan,
    DiagNavActiveLog,
    DiagNavConfirm,
    DiagNavText,
} DiagNavPage;

typedef struct {
    DiagNavPage current;
    DiagNavPage history[DIAG_NAV_HISTORY_CAPACITY];
    size_t depth;
} DiagNavigation;

_Static_assert(sizeof(DiagNavigation) <= 96u, "Navigation state exceeds RAM budget");

static inline void diag_navigation_init(DiagNavigation* navigation, DiagNavPage page) {
    navigation->current = page;
    navigation->depth = 0;
}

static inline DiagNavPage diag_navigation_current(const DiagNavigation* navigation) {
    return navigation->current;
}

static inline void diag_navigation_enter(DiagNavigation* navigation, DiagNavPage page) {
    if(navigation->current == page) return;
    if(navigation->depth == DIAG_NAV_HISTORY_CAPACITY) {
        for(size_t i = 1; i < DIAG_NAV_HISTORY_CAPACITY; ++i)
            navigation->history[i - 1] = navigation->history[i];
        navigation->depth--;
    }
    navigation->history[navigation->depth++] = navigation->current;
    navigation->current = page;
}

static inline void diag_navigation_replace(DiagNavigation* navigation, DiagNavPage page) {
    navigation->current = page;
}

static inline bool diag_navigation_back(DiagNavigation* navigation) {
    if(!navigation->depth) return false;
    navigation->current = navigation->history[--navigation->depth];
    return true;
}

static inline void diag_navigation_present_text(DiagNavigation* navigation) {
    if(navigation->current == DiagNavActiveLog) diag_navigation_back(navigation);
    if(navigation->current == DiagNavActiveScan || navigation->current == DiagNavConfirm)
        diag_navigation_replace(navigation, DiagNavText);
    else
        diag_navigation_enter(navigation, DiagNavText);
}

static inline void diag_navigation_finish_activity(
    DiagNavigation* navigation,
    DiagNavPage result) {
    if(navigation->current == DiagNavActiveLog) diag_navigation_back(navigation);
    diag_navigation_replace(navigation, result);
}

/* A band handoff continues the same operation even when its log was open. */
static inline void diag_navigation_start_activity(DiagNavigation* navigation) {
    if(navigation->current == DiagNavActiveLog) diag_navigation_back(navigation);
    diag_navigation_enter(navigation, DiagNavActiveScan);
}

static inline void diag_navigation_return_to(DiagNavigation* navigation, DiagNavPage page) {
    if(navigation->current == page) return;
    while(navigation->depth) {
        DiagNavPage previous = navigation->history[--navigation->depth];
        if(previous == page) {
            navigation->current = page;
            return;
        }
    }
    navigation->current = page;
}

#endif
