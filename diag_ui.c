#include "diag_ui.h"
#include <stdio.h>
#include <string.h>
const char* const diag_menu_items[DIAG_MENU_COUNT] = {
    "Identify card (auto)", "Results", "Live event log", "Diagnose", "Save + export",
    "Saved sessions", "Browse / validate .nfc", "Set baseline", "Compare sessions",
    "Repeat test (5 runs)", "Protocol reference", "Simulated tests", "USB diagnostics", "About",
    "Scan 125 kHz RFID", "Reader diagnostics", "Card workflow", "Browse / validate .rfid",
    "Nonce library",
};
const char* const diag_reader_menu_items[6] = {
    "Find reader band", "NFC field monitor", "Type A requests", "Classic nonces", "LF field monitor", "Last reader report",
};
const char* const diag_workflow_start_items[3] = {"I have a card", "I have no card", "Continue workflow"};
const char* const diag_workflow_menu_items[16] = {
    "Guide / next steps", "Find card (both bands)", "Reader diagnostics", "Read NFC / save", "Read LF / save",
    "Choose source .nfc", "Choose source .rfid", "Capture Classic nonces", "Decode with MFKey",
    "Write NFC blank", "Write LF blank", "Verify saved copy", "Save diagnostics", "New workflow", "Try HID iClass", "Nonce library",
};

void diag_ui_menu(DiagUi* ui, const char* title, const char* const* items, size_t count) {
    snprintf(ui->title, sizeof(ui->title), "%s", title);
    ui->menu_items = items;
    ui->menu_count = count;
    ui->selected = 0;
    ui->menu = true;
    ui->scanning = false;
}
void diag_ui_text(DiagUi* ui, const char* title, const char* text, bool preserve_scroll) {
    size_t old_scroll = ui->scroll;
    snprintf(ui->title, sizeof(ui->title), "%s", title);
    snprintf(ui->text, sizeof(ui->text), "%s", text);
    ui->menu = false;
    ui->line_count = 0;
    size_t offset = 0;
    while(ui->text[offset] && ui->line_count < DIAG_UI_LINES) {
        size_t length = 0;
        while(ui->text[offset + length] && ui->text[offset + length] != '\n' && length < 21)
            length++;
        if(length == 21 && ui->text[offset + length] && ui->text[offset + length] != '\n') {
            size_t space = length;
            while(space && ui->text[offset + space] != ' ') space--;
            if(space) length = space;
        }
        ui->offsets[ui->line_count] = offset;
        ui->lengths[ui->line_count++] = length;
        offset += length;
        if(ui->text[offset] == '\n') offset++;
        else if(ui->text[offset] == ' ') offset++;
    }
    if(!ui->line_count) {
        ui->offsets[0] = 0;
        ui->lengths[0] = 0;
        ui->line_count = 1;
    }
    size_t max_scroll = ui->line_count > 5 ? ui->line_count - 5 : 0;
    ui->scroll = preserve_scroll && old_scroll < max_scroll ? old_scroll :
                 preserve_scroll ? max_scroll : 0;
}
void diag_ui_move(DiagUi* ui, int direction) {
    size_t* position = ui->menu ? &ui->selected : &ui->scroll;
    size_t limit = ui->menu ? (ui->menu_count ? ui->menu_count : DIAG_MENU_COUNT) - 1 :
                   ui->line_count > 5 ? ui->line_count - 5 : 0;
    if(direction < 0 && *position) (*position)--;
    if(direction > 0 && *position < limit) (*position)++;
}
void diag_ui_draw(Canvas* canvas, const DiagUi* ui) {
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    char position[20];
    if(ui->menu) {
        canvas_draw_str(canvas, 2, 8, ui->title[0] ? ui->title : "NFC Diagnostic Suite");
        canvas_draw_line(canvas, 0, 11, 127, 11);
        size_t start = ui->selected > 3 ? ui->selected - 3 : 0;
        for(size_t row = 0; row < 4 && start + row < (ui->menu_count ? ui->menu_count : DIAG_MENU_COUNT); row++) {
            size_t index = start + row;
            int y = 22 + row * 10;
            if(index == ui->selected) {
                canvas_draw_box(canvas, 0, y - 8, 128, 10);
                canvas_set_color(canvas, ColorWhite);
            }
            canvas_draw_str(canvas, 3, y, (ui->menu_items ? ui->menu_items : diag_menu_items)[index]);
            canvas_set_color(canvas, ColorBlack);
        }
        canvas_draw_str(canvas, 2, 63, ui->menu_items == diag_menu_items || !ui->menu_items ?
            "OK: open      Back: exit" : "OK: open    Back: return");
    } else {
        snprintf(position, sizeof(position), "%u/%u", (unsigned)(ui->scroll + 1),
                 (unsigned)ui->line_count);
        int position_x = 124 - canvas_string_width(canvas, position);
        char title[sizeof(ui->title)];
        snprintf(title, sizeof(title), "%s", ui->title);
        size_t title_length = strlen(title);
        while(title_length && canvas_string_width(canvas, title) > position_x - 5)
            title[--title_length] = 0;
        canvas_draw_str(canvas, 1, 8, title);
        canvas_draw_str(canvas, position_x, 8, position);
        canvas_draw_line(canvas, 0, 11, 127, 11);
        canvas_set_font(canvas, FontKeyboard);
        for(size_t row = 0; row < 5 && ui->scroll + row < ui->line_count; row++) {
            size_t index = ui->scroll + row;
            char line[22];
            memcpy(line, ui->text + ui->offsets[index], ui->lengths[index]);
            line[ui->lengths[index]] = 0;
            canvas_draw_str(canvas, 0, 21 + row * 9, line);
        }
        if(ui->scanning) {
            if(ui->run_number) {
                unsigned width = ui->run_number * 25;
                canvas_draw_box(canvas, 0, 60, width > 128 ? 128 : width, 3);
            } else {
                unsigned phase = ui->animation_frame % 40;
                unsigned x = (phase <= 20 ? phase : 40 - phase) * 5;
                canvas_draw_box(canvas, x, 60, 24, 3);
            }
        }
    }
}
