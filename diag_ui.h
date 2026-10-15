#pragma once
#include <gui/canvas.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "diag_model.h"
#define DIAG_UI_TEXT_SIZE 2048
#define DIAG_MENU_COUNT 6

typedef enum {
    DiagUiArtNone,
    DiagUiArtCard,
    DiagUiArtReader,
    DiagUiArtScanning,
    DiagUiArtSuccess,
    DiagUiArtError,
} DiagUiArt;

typedef struct {
    char title[32];
    char text[DIAG_UI_TEXT_SIZE];
    size_t line_count;
    size_t scroll;
    size_t selected;
    const char* const* menu_items;
    size_t menu_count;
    bool menu;
    bool scanning;
    bool log_view;
    bool step;
    DiagUiArt art;
    char left[12];
    char center[12];
    char right[12];
    unsigned run_number;
    unsigned animation_frame;
} DiagUi;
extern const char* const diag_menu_items[DIAG_MENU_COUNT];
extern const char* const diag_reader_menu_items[6];
extern const char* const diag_saved_menu_items[2];
extern const char* const diag_session_menu_items[6];
extern const char* const diag_workflow_start_items[2];
extern const char* const diag_workflow_menu_items[16];
void diag_ui_menu(DiagUi* ui, const char* title, const char* const* items, size_t count);
void diag_ui_text(DiagUi* ui, const char* title, const char* text, bool preserve_scroll);
/* Formats only the visible window; retains no model pointer. Call again after
   changing the model, scanning state, or scroll (including inactive logs). */
void diag_ui_logs(DiagUi* ui, const DiagModel* model, bool preserve_scroll, bool follow);
void diag_ui_step(
    DiagUi* ui, const char* title, const char* body, DiagUiArt art,
    const char* left, const char* center, const char* right);
void diag_ui_draw(Canvas* canvas, const DiagUi* ui);
void diag_ui_move(DiagUi* ui, int direction);
