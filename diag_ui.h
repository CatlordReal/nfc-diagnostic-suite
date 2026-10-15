#pragma once
#include <gui/canvas.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define DIAG_UI_TEXT_SIZE 8192
#define DIAG_UI_LINES 512
#define DIAG_MENU_COUNT 19

typedef struct {
    char title[32];
    char text[DIAG_UI_TEXT_SIZE];
    uint16_t offsets[DIAG_UI_LINES];
    uint8_t lengths[DIAG_UI_LINES];
    size_t line_count;
    size_t scroll;
    size_t selected;
    const char* const* menu_items;
    size_t menu_count;
    bool menu;
    bool scanning;
    unsigned run_number;
    unsigned animation_frame;
} DiagUi;
extern const char* const diag_menu_items[DIAG_MENU_COUNT];
extern const char* const diag_reader_menu_items[6];
extern const char* const diag_workflow_start_items[3];
extern const char* const diag_workflow_menu_items[16];
void diag_ui_menu(DiagUi* ui, const char* title, const char* const* items, size_t count);
void diag_ui_text(DiagUi* ui, const char* title, const char* text, bool preserve_scroll);
void diag_ui_draw(Canvas* canvas, const DiagUi* ui);
void diag_ui_move(DiagUi* ui, int direction);
