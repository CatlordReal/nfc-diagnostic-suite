#include <assert.h>
#include <stdio.h>
#include "../diag_navigation.h"

static void expect_back(DiagNavigation* navigation, DiagNavPage page) {
    assert(diag_navigation_back(navigation));
    assert(diag_navigation_current(navigation) == page);
}

static void test_root_reader_returns_home(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavReader);
    expect_back(&navigation, DiagNavHome);
    assert(!diag_navigation_back(&navigation));
}

static void test_workflow_reader_preserves_actual_origin(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavWorkflowStart);
    diag_navigation_enter(&navigation, DiagNavWorkflow);
    diag_navigation_enter(&navigation, DiagNavWorkflowTools);
    diag_navigation_enter(&navigation, DiagNavReader);
    expect_back(&navigation, DiagNavWorkflowTools);

    diag_navigation_return_to(&navigation, DiagNavWorkflow);
    diag_navigation_enter(&navigation, DiagNavReader);
    expect_back(&navigation, DiagNavWorkflow);
}

static void test_nested_picker_and_details(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavWorkflowStart);
    diag_navigation_enter(&navigation, DiagNavWorkflow);
    diag_navigation_enter(&navigation, DiagNavSaved);
    expect_back(&navigation, DiagNavWorkflow);

    diag_navigation_enter(&navigation, DiagNavWorkflowTools);
    diag_navigation_enter(&navigation, DiagNavText);
    expect_back(&navigation, DiagNavWorkflowTools);

    diag_navigation_return_to(&navigation, DiagNavWorkflow);
    diag_navigation_enter(&navigation, DiagNavText);
    expect_back(&navigation, DiagNavWorkflow);
}

static void test_file_browser_cancel_and_error_origins(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavSaved);
    assert(diag_navigation_current(&navigation) == DiagNavSaved); /* Native browser cancel. */
    diag_navigation_present_text(&navigation); /* Validation error. */
    expect_back(&navigation, DiagNavSaved);
    expect_back(&navigation, DiagNavHome);

    diag_navigation_enter(&navigation, DiagNavSessions);
    diag_navigation_present_text(&navigation);
    expect_back(&navigation, DiagNavSessions);
}

static void test_active_log_cancel_and_outcome(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavReader);
    diag_navigation_enter(&navigation, DiagNavActiveScan);
    diag_navigation_enter(&navigation, DiagNavActiveLog);
    expect_back(&navigation, DiagNavActiveScan);

    diag_navigation_finish_activity(&navigation, DiagNavWorkflow);
    expect_back(&navigation, DiagNavReader);

    diag_navigation_enter(&navigation, DiagNavActiveScan);
    expect_back(&navigation, DiagNavReader);

    diag_navigation_enter(&navigation, DiagNavActiveScan);
    diag_navigation_enter(&navigation, DiagNavActiveLog);
    diag_navigation_finish_activity(&navigation, DiagNavWorkflow);
    expect_back(&navigation, DiagNavReader);

    diag_navigation_enter(&navigation, DiagNavActiveScan);
    diag_navigation_enter(&navigation, DiagNavActiveLog);
    diag_navigation_present_text(&navigation);
    assert(diag_navigation_current(&navigation) == DiagNavText);
    expect_back(&navigation, DiagNavReader);
}

static void test_error_confirm_and_resume(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavWorkflow);
    diag_navigation_enter(&navigation, DiagNavWorkflowTools);
    diag_navigation_enter(&navigation, DiagNavConfirm);
    diag_navigation_present_text(&navigation);
    assert(diag_navigation_current(&navigation) == DiagNavText);
    expect_back(&navigation, DiagNavWorkflowTools);

    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavWorkflow);
    diag_navigation_enter(&navigation, DiagNavText);
    expect_back(&navigation, DiagNavWorkflow);
    expect_back(&navigation, DiagNavHome);
}

static void test_stack_bound_keeps_recent_path(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    for(size_t i = 0; i < DIAG_NAV_HISTORY_CAPACITY + 9u; ++i)
        diag_navigation_enter(&navigation, i % 2 ? DiagNavReader : DiagNavSessions);
    assert(navigation.depth == DIAG_NAV_HISTORY_CAPACITY);
    for(size_t i = 0; i < DIAG_NAV_HISTORY_CAPACITY; ++i)
        assert(diag_navigation_back(&navigation));
    assert(!diag_navigation_back(&navigation));
}

static void test_band_handoff_from_live_log_keeps_caller(void) {
    DiagNavigation navigation;
    diag_navigation_init(&navigation, DiagNavHome);
    diag_navigation_enter(&navigation, DiagNavReader);
    diag_navigation_start_activity(&navigation);
    diag_navigation_enter(&navigation, DiagNavActiveLog);
    diag_navigation_start_activity(&navigation);
    assert(diag_navigation_current(&navigation) == DiagNavActiveScan);
    diag_navigation_finish_activity(&navigation, DiagNavWorkflow);
    expect_back(&navigation, DiagNavReader);
    expect_back(&navigation, DiagNavHome);
    assert(!diag_navigation_back(&navigation));
}

int main(void) {
    test_band_handoff_from_live_log_keeps_caller();
    test_root_reader_returns_home();
    test_workflow_reader_preserves_actual_origin();
    test_nested_picker_and_details();
    test_file_browser_cancel_and_error_origins();
    test_active_log_cancel_and_outcome();
    test_error_confirm_and_resume();
    test_stack_bound_keeps_recent_path();
    puts("navigation tests passed");
    return 0;
}
