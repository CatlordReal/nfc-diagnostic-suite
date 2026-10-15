#include "diag_ui.h"
#include <assets_icons.h>
#include <gui/elements.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DIAG_UI_HOST_RENDER
void canvas_draw_icon(Canvas* canvas, int x, int y, const Icon* icon);
size_t diag_ui_host_free_heap(void);
size_t diag_ui_host_max_free_block(void);
void* diag_ui_host_alloc(size_t size);
void diag_ui_host_free(void* pointer);
#else
#include <furi/core/memmgr.h>
#include <furi/core/memmgr_heap.h>
#endif

#define DIAG_UI_COLUMNS 21u
#define DIAG_UI_ROW_PITCH 10u
_Static_assert(sizeof(DiagUi) <= 416u, "Keep permanent UI memory below 416 bytes");

const char* const diag_menu_items[DIAG_MENU_COUNT] = {
    "Workflow", "Reader diagnostics", "Saved cards", "Sessions", "Protocol reference", "About",
};
const char* const diag_saved_menu_items[2] = {"NFC files", "RFID files"};
const char* const diag_session_menu_items[8] = {
    "Open session", "Use as reference", "Compare with reference", "Read 5 times", "Event log", "Diagnose", "System", "Reader patterns",
};
const char* const diag_reader_menu_items[6] = {
    "Find reader band", "NFC field monitor", "Type A requests", "Classic nonces", "LF field monitor", "Last reader report",
};
const char* const diag_workflow_start_items[2] = {"I have the card", "I only have the reader"};
const char* const diag_workflow_menu_items[16] = {
    "Details", "Find card (both bands)", "Reader diagnostics", "Read NFC / save", "Read LF / save",
    "Choose source .nfc", "Choose source .rfid", "Capture Classic nonces", "Decode with MFKey",
    "Write NFC blank", "Write LF blank", "Verify saved copy", "Save diagnostics", "New workflow", "Try HID iClass", "Nonce library",
};

static size_t ui_rows(const DiagUi* ui) {
    return ui->scanning ? 4u : 5u;
}

/* Returns the next line and advances past one explicit newline or wrap space.
   No per-line index is retained in permanent UI memory. */
static size_t ui_next_line(const char** cursor, size_t columns, char* output) {
    const char* text = *cursor;
    size_t size = 0;
    while(text[size] && text[size] != '\n' && size < columns) ++size;
    if(size == columns && text[size] && text[size] != '\n') {
        size_t space = size;
        while(space && text[space] != ' ') --space;
        if(space) size = space;
    }
    if(output) {
        memcpy(output, text, size);
        output[size] = '\0';
    }
    text += size;
    if(*text == '\n' || *text == ' ') ++text;
    *cursor = text;
    return size;
}

static size_t ui_count_lines(const char* text) {
    size_t count = 0;
    while(*text) {
        ui_next_line(&text, DIAG_UI_COLUMNS, NULL);
        ++count;
    }
    return count ? count : 1u;
}

static size_t ui_bottom(const DiagUi* ui) {
    size_t rows = ui_rows(ui);
    return ui->line_count > rows ? ui->line_count - rows : 0u;
}

static void ui_release_detail(DiagUi* ui) {
    if(!ui->detail_text) return;
#ifdef DIAG_UI_HOST_RENDER
    diag_ui_host_free(ui->detail_text);
#else
    free(ui->detail_text);
#endif
    ui->detail_text = NULL;
    ui->detail_capacity = 0;
}

void diag_ui_free(DiagUi* ui) {
    if(ui) ui_release_detail(ui);
}

void diag_ui_prepare_radio(DiagUi* ui) {
    if(!ui) return;
    ui_release_detail(ui);
    ui->text[0] = '\0';
    ui->line_count = 1;
    ui->scroll = 0;
}

static const char* ui_content(const DiagUi* ui) {
    return ui->detail_text ? ui->detail_text : ui->text;
}

static bool ui_detail_fits(size_t size) {
    const size_t allocation = (size + 8u + 7u) & ~(size_t)7u;
#ifdef DIAG_UI_HOST_RENDER
    return diag_ui_host_free_heap() >= allocation + 2048u &&
        diag_ui_host_max_free_block() >= allocation;
#else
    return memmgr_get_free_heap() >= allocation + 2048u &&
        memmgr_heap_get_max_free_block() >= allocation;
#endif
}

static void ui_set_text(
    DiagUi* ui, const char* title, const char* text, bool preserve_scroll, bool allow_detail) {
    const size_t old_scroll = ui->scroll;
    if(!text) text = "";
    size_t size = 0;
    while(size <= DIAG_UI_DETAIL_TEXT_LIMIT && text[size]) ++size;
    const bool truncated = size > DIAG_UI_DETAIL_TEXT_LIMIT;
    if(truncated) size = DIAG_UI_DETAIL_TEXT_LIMIT;
    snprintf(ui->title, sizeof(ui->title), "%s", title ? title : "");
    if(size < sizeof(ui->text)) {
        memmove(ui->text, text, size);
        ui->text[size] = '\0';
        ui_release_detail(ui);
    } else if(allow_detail) {
        if(ui->detail_capacity < size + 1u) {
            ui_release_detail(ui);
            if(ui_detail_fits(size + 1u)) {
#ifdef DIAG_UI_HOST_RENDER
                ui->detail_text = diag_ui_host_alloc(size + 1u);
#else
                ui->detail_text = malloc(size + 1u);
#endif
                if(ui->detail_text) ui->detail_capacity = size + 1u;
            }
        }
        if(ui->detail_text) {
            memmove(ui->detail_text, text, size);
            ui->detail_text[size] = '\0';
            if(truncated) {
                static const char suffix[] = "\n[Text truncated]";
                memcpy(ui->detail_text + size - sizeof(suffix) + 1u, suffix, sizeof(suffix));
            }
        } else {
            snprintf(ui->text, sizeof(ui->text), "Details shortened:\nLow memory.\n%.210s", text);
        }
    } else {
        /* RF callbacks and step bodies never allocate a detail buffer. */
        snprintf(ui->text, sizeof(ui->text), "Details shortened.\n%.230s", text);
        ui_release_detail(ui);
    }
    ui->menu = false;
    ui->step = false;
    ui->log_view = false;
    ui->line_count = ui_count_lines(ui_content(ui));
    const size_t bottom = ui_bottom(ui);
    ui->scroll = preserve_scroll ? (old_scroll < bottom ? old_scroll : bottom) : 0;
}

void diag_ui_menu(DiagUi* ui, const char* title, const char* const* items, size_t count) {
    ui_release_detail(ui);
    snprintf(ui->title, sizeof(ui->title), "%s", title ? title : "");
    ui->menu_items = items ? items : diag_menu_items;
    ui->menu_count = items ? count : DIAG_MENU_COUNT;
    ui->selected = 0;
    ui->scroll = 0;
    ui->menu = true;
    ui->step = false;
    ui->log_view = false;
    ui->scanning = false;
}

void diag_ui_text(DiagUi* ui, const char* title, const char* text, bool preserve_scroll) {
    ui_set_text(ui, title, text, preserve_scroll, !ui->scanning);
}

static void ui_log_entry(const DiagModel* model, size_t entry, char* output, size_t capacity) {
    if(model->logs_dropped && entry == 0) {
        snprintf(output, capacity, "Dropped: %lu older events", (unsigned long)model->logs_dropped);
        return;
    }
    if(model->logs_dropped) --entry;
    if(entry >= model->log_count || entry >= DIAG_MAX_LOGS) {
        snprintf(output, capacity, "No events yet");
        return;
    }
    const DiagLogEntry* log = &model->logs[entry];
    snprintf(output, capacity, "%lu ms %s\n%.95s", (unsigned long)log->elapsed_ms,
             diag_log_level_name(log->level), log->message);
}

void diag_ui_logs(DiagUi* ui, const DiagModel* model, bool preserve_scroll, bool follow) {
    ui_release_detail(ui);
    size_t old_scroll = ui->scroll;
    ui->menu = false;
    ui->step = false;
    ui->log_view = true;
    snprintf(ui->title, sizeof(ui->title), "Event log");
    size_t entries = model ? (model->log_count < DIAG_MAX_LOGS ? model->log_count : DIAG_MAX_LOGS) +
                            (model->logs_dropped ? 1u : 0u) : 0;
    ui->line_count = 0;
    char entry[160];
    for(size_t index = 0; index < entries; ++index) {
        ui_log_entry(model, index, entry, sizeof(entry));
        ui->line_count += ui_count_lines(entry);
    }
    if(!ui->line_count) ui->line_count = 1;
    size_t bottom = ui_bottom(ui);
    ui->scroll = follow ? bottom : preserve_scroll ? (old_scroll < bottom ? old_scroll : bottom) : 0;
    ui->text[0] = '\0';
    size_t logical = 0, used = 0, shown = 0;
    for(size_t index = 0; index < entries && shown < ui_rows(ui); ++index) {
        ui_log_entry(model, index, entry, sizeof(entry));
        const char* cursor = entry;
        while(*cursor && shown < ui_rows(ui)) {
            char line[DIAG_UI_COLUMNS + 1u];
            size_t size = ui_next_line(&cursor, DIAG_UI_COLUMNS, line);
            if(logical++ < ui->scroll) continue;
            if(used + size + 2u < sizeof(ui->text)) {
                memcpy(ui->text + used, line, size);
                used += size;
                ui->text[used++] = '\n';
                ui->text[used] = '\0';
            }
            ++shown;
        }
    }
    if(!entries) snprintf(ui->text, sizeof(ui->text), "No events yet");
}

void diag_ui_step(
    DiagUi* ui, const char* title, const char* body, DiagUiArt art,
    const char* left, const char* center, const char* right) {
    ui_set_text(ui, title, body, false, false);
    ui->step = true;
    ui->art = art;
    ui->scanning = art == DiagUiArtScanning;
    snprintf(ui->left, sizeof(ui->left), "%s", left ? left : "");
    snprintf(ui->center, sizeof(ui->center), "%s", center ? center : "");
    snprintf(ui->right, sizeof(ui->right), "%s", right ? right : "");
}

void diag_ui_move(DiagUi* ui, int direction) {
    if(!direction) return;
    if(ui->menu) {
        size_t count = ui->menu_count;
        if(!count) return;
        if(ui->selected >= count) ui->selected = 0;
        ui->selected = direction < 0 ? (ui->selected ? ui->selected - 1u : count - 1u) :
                                      (ui->selected + 1u == count ? 0u : ui->selected + 1u);
    } else if(!ui->step) {
        size_t bottom = ui_bottom(ui);
        if(ui->scroll > bottom) ui->scroll = bottom;
        if(direction < 0 && ui->scroll) --ui->scroll;
        if(direction > 0 && ui->scroll < bottom) ++ui->scroll;
    }
}

static void ui_progress(Canvas* canvas, const DiagUi* ui, int y) {
    if(ui->run_number) {
        unsigned width = ui->run_number * 25u;
        canvas_draw_box(canvas, 0, y, width > 128u ? 128u : width, 2);
    } else {
        unsigned phase = ui->animation_frame % 40u;
        unsigned x = (phase <= 20u ? phase : 40u - phase) * 5u;
        canvas_draw_box(canvas, (int)x, y, 24, 2);
    }
}

static void ui_step_draw(Canvas* canvas, const DiagUi* ui) {
    int text_x = 2, title_x = 2, body_y = 25;
    size_t columns = DIAG_UI_COLUMNS;
    switch(ui->art) {
    case DiagUiArtCard:
        canvas_draw_icon(canvas, 7, 23, &I_RFIDSmallChip_14x14);
        text_x = 28; columns = 16; break;
    case DiagUiArtReader:
        canvas_draw_icon(canvas, 8, 25, &I_Nfc_10px);
        text_x = 25; columns = 17; break;
    case DiagUiArtScanning:
        canvas_draw_icon(canvas, 0, 0, &I_DolphinWait_59x54);
        text_x = title_x = 63; columns = 12; body_y = 24; break;
    case DiagUiArtSuccess:
        canvas_draw_icon(canvas, 0, 0, &I_DolphinReadingSuccess_59x63);
        text_x = title_x = 63; columns = 12; body_y = 27; break;
    case DiagUiArtError:
        canvas_draw_icon(canvas, 0, 8, &I_WarningDolphin_45x42);
        text_x = title_x = 50; columns = 14; break;
    case DiagUiArtNone: break;
    }
    canvas_set_font(canvas, FontSecondary);
    char title[sizeof(ui->title)];
    snprintf(title, sizeof(title), "%s", ui->title);
    size_t size = strlen(title);
    while(size && canvas_string_width(canvas, title) > 127 - title_x) title[--size] = '\0';
    canvas_draw_str(canvas, title_x, 10, title);
    const char* cursor = ui_content(ui);
    for(size_t row = 0; *cursor && row < 3; ++row) {
        char line[DIAG_UI_COLUMNS + 1u];
        ui_next_line(&cursor, columns, line);
        canvas_draw_str(canvas, text_x, body_y + (int)row * DIAG_UI_ROW_PITCH, line);
    }
    if(ui->scanning) ui_progress(canvas, ui, 49);
    /* Clear the button row after the native art, which can span the full LCD. */
    canvas_set_color(canvas, ColorWhite);
    canvas_draw_box(canvas, 0, 51, 128, 13);
    canvas_set_color(canvas, ColorBlack);
    if(ui->left[0]) elements_button_left(canvas, ui->left);
    if(ui->center[0]) elements_button_center(canvas, ui->center);
    if(ui->right[0]) elements_button_right(canvas, ui->right);
}

void diag_ui_draw(Canvas* canvas, const DiagUi* ui) {
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    if(ui->step) {
        ui_step_draw(canvas, ui);
        return;
    }
    if(ui->menu) {
        canvas_draw_str(canvas, 2, 8, ui->title[0] ? ui->title : "NFC Diagnostic Suite");
        canvas_draw_line(canvas, 0, 11, 127, 11);
        size_t start = ui->selected >= 5u ? ui->selected - 4u : 0u;
        for(size_t row = 0; row < 5u && start + row < ui->menu_count; ++row) {
            size_t index = start + row;
            int y = 21 + (int)row * DIAG_UI_ROW_PITCH;
            if(index == ui->selected) {
                canvas_draw_box(canvas, 2, y - 7, 124, 8);
                canvas_draw_line(canvas, 1, y - 6, 1, y - 1);
                canvas_draw_line(canvas, 126, y - 6, 126, y - 1);
                canvas_set_color(canvas, ColorWhite);
            }
            canvas_draw_str(canvas, 4, y, ui->menu_items[index]);
            canvas_set_color(canvas, ColorBlack);
        }
        return;
    }
    char position[24];
    snprintf(position, sizeof(position), "%u/%u", (unsigned)(ui->scroll + 1u), (unsigned)ui->line_count);
    int position_x = 126 - canvas_string_width(canvas, position);
    char title[sizeof(ui->title)];
    snprintf(title, sizeof(title), "%s", ui->title);
    size_t size = strlen(title);
    while(size && canvas_string_width(canvas, title) > position_x - 4) title[--size] = '\0';
    canvas_draw_str(canvas, 1, 8, title);
    canvas_draw_str(canvas, position_x, 8, position);
    canvas_draw_line(canvas, 0, 11, 127, 11);
    canvas_set_font(canvas, FontKeyboard);
    const char* cursor = ui_content(ui);
    if(!ui->log_view) {
        for(size_t skip = 0; *cursor && skip < ui->scroll; ++skip)
            ui_next_line(&cursor, DIAG_UI_COLUMNS, NULL);
    }
    for(size_t row = 0; *cursor && row < ui_rows(ui); ++row) {
        char line[DIAG_UI_COLUMNS + 1u];
        ui_next_line(&cursor, DIAG_UI_COLUMNS, line);
        canvas_draw_str(canvas, 0, 21 + (int)row * DIAG_UI_ROW_PITCH, line);
    }
    if(ui->scanning) ui_progress(canvas, ui, 61);
}
