#include "diag_systems_ui.h"

#include <furi.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/view_dispatcher.h>

#include <string.h>

enum {
    DiagSystemViewList = 0,
    DiagSystemViewName,
    DiagSystemMenuUngrouped = 0,
    DiagSystemMenuNew,
    DiagSystemMenuFirstGroup,
};

typedef struct {
    ViewDispatcher* dispatcher;
    TextInput* input;
    DiagSystemList list;
    char choice[DIAG_SYSTEM_NAME_CAPACITY];
    char new_name[DIAG_SYSTEM_NAME_CAPACITY];
    bool entering_name;
    bool accepted;
    bool create;
} DiagSystemChooser;

static void diag_system_chooser_name_done(void* context);

static bool diag_system_chooser_equal_ci(const char* left, const char* right) {
    while(*left && *right) {
        char a = *left++;
        char b = *right++;
        if(a >= 'a' && a <= 'z') a = (char)(a - ('a' - 'A'));
        if(b >= 'a' && b <= 'z') b = (char)(b - ('a' - 'A'));
        if(a != b) return false;
    }
    return *left == *right;
}

static void diag_system_chooser_select(void* context, uint32_t index) {
    DiagSystemChooser* chooser = context;
    if(index == DiagSystemMenuNew) {
        chooser->new_name[0] = '\0';
        text_input_set_result_callback(
            chooser->input,
            diag_system_chooser_name_done,
            chooser,
            chooser->new_name,
            sizeof(chooser->new_name),
            false);
        chooser->entering_name = true;
        view_dispatcher_switch_to_view(chooser->dispatcher, DiagSystemViewName);
        return;
    }
    chooser->choice[0] = '\0';
    if(index >= DiagSystemMenuFirstGroup) {
        const size_t position = index - DiagSystemMenuFirstGroup;
        if(position >= chooser->list.count) return;
        memcpy(
            chooser->choice,
            chooser->list.names[position],
            strlen(chooser->list.names[position]) + 1u);
    }
    chooser->accepted = true;
    view_dispatcher_stop(chooser->dispatcher);
}

static bool diag_system_chooser_validate(
    const char* text,
    FuriString* error,
    void* context) {
    UNUSED(context);
    const bool valid = text[0] && diag_system_name_valid(text);
    if(!valid) furi_string_set(error, "Use 1-24 safe ASCII\ncharacters.");
    return valid;
}

static void diag_system_chooser_name_done(void* context) {
    DiagSystemChooser* chooser = context;
    memcpy(chooser->choice, chooser->new_name, strlen(chooser->new_name) + 1u);
    chooser->create = true;
    for(size_t index = 0u; index < chooser->list.count; ++index) {
        if(diag_system_chooser_equal_ci(chooser->choice, chooser->list.names[index])) {
            memcpy(
                chooser->choice,
                chooser->list.names[index],
                strlen(chooser->list.names[index]) + 1u);
            chooser->create = false;
            break;
        }
    }
    chooser->accepted = true;
    view_dispatcher_stop(chooser->dispatcher);
}

static bool diag_system_chooser_back(void* context) {
    DiagSystemChooser* chooser = context;
    if(!chooser->entering_name) return false;
    chooser->entering_name = false;
    view_dispatcher_switch_to_view(chooser->dispatcher, DiagSystemViewList);
    return true;
}

bool diag_system_choose(
    Storage* storage,
    Gui* gui,
    char name[DIAG_SYSTEM_NAME_CAPACITY],
    FuriString* explanation) {
    if(explanation) furi_string_set(explanation, "");
    if(!storage || !gui || !name || !diag_system_name_valid(name)) return false;

    DiagSystemChooser chooser = {0};
    if(diag_system_list(storage, &chooser.list, explanation) != DiagFileStatusOk) return false;

    chooser.dispatcher = view_dispatcher_alloc();
    Submenu* submenu = submenu_alloc();
    TextInput* input = text_input_alloc();
    chooser.input = input;
    view_dispatcher_set_event_callback_context(chooser.dispatcher, &chooser);
    view_dispatcher_set_navigation_event_callback(
        chooser.dispatcher, diag_system_chooser_back);
    view_dispatcher_attach_to_gui(
        chooser.dispatcher, gui, ViewDispatcherTypeFullscreen);

    submenu_set_header(submenu, "Systems");
    submenu_add_item(
        submenu,
        "Ungrouped",
        DiagSystemMenuUngrouped,
        diag_system_chooser_select,
        &chooser);
    if(!chooser.list.truncated && chooser.list.count < DIAG_SYSTEM_MAX_GROUPS) {
        submenu_add_item(
            submenu,
            "New system",
            DiagSystemMenuNew,
            diag_system_chooser_select,
            &chooser);
    }
    uint32_t selected = DiagSystemMenuUngrouped;
    for(size_t index = 0u; index < chooser.list.count; ++index) {
        const uint32_t item = (uint32_t)index + DiagSystemMenuFirstGroup;
        submenu_add_item(
            submenu,
            chooser.list.names[index],
            item,
            diag_system_chooser_select,
            &chooser);
        if(!strcmp(name, chooser.list.names[index])) selected = item;
    }
    submenu_set_selected_item(submenu, selected);

    text_input_set_header_text(input, "New system");
    text_input_set_minimum_length(input, 1u);
    text_input_show_illegal_symbols(input, false);
    text_input_set_validator(input, diag_system_chooser_validate, NULL);
    text_input_set_result_callback(
        input,
        diag_system_chooser_name_done,
        &chooser,
        chooser.new_name,
        sizeof(chooser.new_name),
        false);

    view_dispatcher_add_view(
        chooser.dispatcher, DiagSystemViewList, submenu_get_view(submenu));
    view_dispatcher_add_view(
        chooser.dispatcher, DiagSystemViewName, text_input_get_view(input));
    view_dispatcher_switch_to_view(chooser.dispatcher, DiagSystemViewList);
    view_dispatcher_run(chooser.dispatcher);

    view_dispatcher_remove_view(chooser.dispatcher, DiagSystemViewName);
    view_dispatcher_remove_view(chooser.dispatcher, DiagSystemViewList);
    text_input_free(input);
    submenu_free(submenu);
    view_dispatcher_free(chooser.dispatcher);

    if(!chooser.accepted) {
        if(explanation) furi_string_set(explanation, "");
        return false;
    }
    if(chooser.create &&
       diag_system_create(storage, chooser.choice, explanation) != DiagFileStatusOk) {
        return false;
    }
    if(diag_system_current_save(storage, chooser.choice, explanation) != DiagFileStatusOk)
        return false;
    memcpy(name, chooser.choice, strlen(chooser.choice) + 1u);
    return true;
}
