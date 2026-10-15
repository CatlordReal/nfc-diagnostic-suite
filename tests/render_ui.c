#include "../diag_ui.h"
#include <assets_icons.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int canvas_string_width(Canvas* canvas, const char* text) {return u8g2_GetStrWidth(canvas, text);}
void canvas_clear(Canvas* canvas) {memset(canvas->tile_buf_ptr, 0, 1024);}
void canvas_set_color(Canvas* canvas, Color color) {u8g2_SetDrawColor(canvas, color == ColorBlack ? 1 : 0);}
void canvas_set_font(Canvas* canvas, Font font) {
    u8g2_SetFontMode(canvas, 1);
    u8g2_SetFont(canvas, font == FontKeyboard ? u8g2_font_profont11_mr : u8g2_font_haxrcorp4089_tr);
}
void canvas_draw_str(Canvas* canvas, int x, int y, const char* text) {u8g2_DrawStr(canvas, x, y, text);}
void canvas_draw_line(Canvas* canvas, int x, int y, int x2, int y2) {u8g2_DrawLine(canvas, x, y, x2, y2);}
void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height) {u8g2_DrawBox(canvas, x, y, width, height);}
void canvas_draw_icon(Canvas* canvas, int x, int y, const Icon* icon) {
    u8g2_DrawXBM(canvas, x, y, icon->width, icon->height, icon->bitmap);
}
static const u8x8_display_info_t display_info = {.tile_width=16,.tile_height=8,.pixel_width=128,.pixel_height=64};
static void capture(Canvas* canvas, DiagUi* ui, const char* directory, const char* name) {
    diag_ui_draw(canvas, ui);
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.pbm", directory, name);
    FILE* file = fopen(path, "wb");
    assert(file);
    fputs("P1\n128 64\n", file);
    for(int y = 0; y < 64; ++y) {
        for(int x = 0; x < 128; ++x)
            fprintf(file, "%u%s", (canvas->tile_buf_ptr[(y/8)*128+x] >> (y%8)) & 1u, x == 127 ? "" : " ");
        fputc('\n', file);
    }
    assert(!fclose(file));
}
static void test_text_and_logs(Canvas* canvas, DiagUi* ui, const char* directory) {
    diag_ui_text(ui, "Card details", "UID: 04 A1 B2 C3 D4 E5 F6\nISO14443-A selected\nATQA: 00 44\nSAK: 00\nCascade levels: 2\nGET_VERSION unsupported\nFamily remains candidate", false);
    assert(ui->line_count > 5);
    capture(canvas, ui, directory, "results");
    for(unsigned i = 0; i < 100; ++i) diag_ui_move(ui, 1);
    assert(ui->scroll == ui->line_count - 5u);
    capture(canvas, ui, directory, "identity");
    for(unsigned i = 0; i < 100; ++i) diag_ui_move(ui, -1);
    assert(ui->scroll == 0);
    DiagModel model;
    diag_model_init(&model, DiagProvenanceSimulation);
    for(unsigned i = 0; i < DIAG_MAX_LOGS + 3u; ++i) {
        char message[96];
        snprintf(message, sizeof(message), "Event %u: selected card; command response remains a candidate until checked", i);
        diag_model_add_log_at(&model, DiagLogInfo, DiagStageProtocolRead, i * 100u, message);
    }
    assert(model.log_count == DIAG_MAX_LOGS && model.logs_dropped == 3u);
    ui->scanning = true;
    diag_ui_logs(ui, &model, false, false);
    size_t total = ui->line_count;
    assert(total > DIAG_MAX_LOGS && ui->scroll == 0);
    assert(strstr(ui->text, "Dropped: 3"));
    assert(strlen(ui->text) < 128u);
    capture(canvas, ui, directory, "log-first");
    for(size_t i = 0; i < total; ++i) {
        diag_ui_move(ui, 1);
        diag_ui_logs(ui, &model, true, false);
        if(i == 3u || i == 7u || i == 11u || i == 15u) {
            char name[24];
            snprintf(name, sizeof(name), "log-%u", (unsigned)(i / 4u));
            capture(canvas, ui, directory, name);
        }
    }
    assert(ui->scroll == total - 4u && strstr(ui->text, "checked\n"));
    capture(canvas, ui, directory, "log");
    diag_ui_logs(ui, &model, true, true);
    assert(ui->scroll == total - 4u);
    ui->scanning = false;
    diag_ui_logs(ui, &model, true, true);
    assert(ui->scroll == total - 5u);
    capture(canvas, ui, directory, "log-last");
    /* Rendering/moving remains safe after the caller's model is gone. */
    memset(&model, 0xA5, sizeof(model));
    diag_ui_move(ui, -1);
    diag_ui_draw(canvas, ui);
    diag_ui_text(ui, "Empty", "", false);
    assert(ui->line_count == 1 && ui->scroll == 0);
}
int main(int argc, char** argv) {
    assert(argc == 2);
    assert(sizeof(DiagUi) < 2300u);
    Canvas canvas = {0};
    uint8_t buffer[1024] = {0};
    canvas.u8x8.display_info = &display_info;
    u8g2_SetupBuffer(&canvas, buffer, 8, u8g2_ll_hvline_vertical_top_lsb, U8G2_R0);
    DiagUi ui = {0};
    diag_ui_menu(&ui, "NFC Diagnostic Suite", diag_menu_items, DIAG_MENU_COUNT);
    capture(&canvas, &ui, argv[1], "menu");
    diag_ui_move(&ui, -1);
    assert(ui.selected == DIAG_MENU_COUNT - 1u);
    capture(&canvas, &ui, argv[1], "menu-wrap");
    diag_ui_move(&ui, 1);
    assert(ui.selected == 0);
    diag_ui_menu(&ui, "What do you have?", diag_workflow_start_items, 2);
    capture(&canvas, &ui, argv[1], "workflow-start");
    diag_ui_move(&ui, 1);
    capture(&canvas, &ui, argv[1], "workflow-reader");
    diag_ui_menu(&ui, "Saved cards", diag_saved_menu_items, 2);
    capture(&canvas, &ui, argv[1], "saved-menu");
    diag_ui_menu(&ui, "Sessions", diag_session_menu_items, 6);
    capture(&canvas, &ui, argv[1], "session-menu");
    diag_ui_menu(&ui, "Reader diagnostics", diag_reader_menu_items, 6);
    capture(&canvas, &ui, argv[1], "reader-menu");
    test_text_and_logs(&canvas, &ui, argv[1]);
    diag_ui_step(&ui, "Read card", "Hold card nearby.\nNFC / LF auto", DiagUiArtCard, "File", "Read", "Tools");
    capture(&canvas, &ui, argv[1], "card-ready");
    diag_ui_step(&ui, "Test reader", "Hold near reader.\nNFC / LF fields", DiagUiArtReader, "File", "Scan", "Tools");
    capture(&canvas, &ui, argv[1], "reader-ready");
    diag_ui_step(&ui, "Reading", "NFC\nIdentity read", DiagUiArtScanning, "File", "", "Log");
    for(unsigned frame = 0; frame < 16; ++frame) {
        char name[32];
        ui.animation_frame = frame * 3u;
        snprintf(name, sizeof(name), "busy-%u", frame);
        capture(&canvas, &ui, argv[1], name);
    }
    diag_ui_step(&ui, "Card inspected", "Ultralight/NTAG2xx\nCommand confirmed\n04A1B2C3D4E5F6", DiagUiArtNone, "File", "Save", "Tools");
    capture(&canvas, &ui, argv[1], "card-outcome");
    diag_ui_step(&ui, "Reader fields", "NFC: yes  LF: no\nField observation\nType not identified", DiagUiArtNone, "File", "Save", "Tests");
    capture(&canvas, &ui, argv[1], "reader-fields");
    diag_ui_step(&ui, "Report saved", "Report files\nsaved on SD", DiagUiArtSuccess, "File", "Done", "Tools");
    capture(&canvas, &ui, argv[1], "saved-step");
    diag_ui_step(&ui, "Check saved copy", "Read blank to a\nNEW file, then\ncompare here.", DiagUiArtCard, "File", "Compare", "Tools");
    capture(&canvas, &ui, argv[1], "verify-copy");
    diag_ui_step(&ui, "Save failed", "SD card\nnot ready", DiagUiArtError, "File", "Retry", "Log");
    capture(&canvas, &ui, argv[1], "error-step");
    printf("UI renderer, virtual log, wrap checks passed; DiagUi host=%zu bytes\n", sizeof(ui));
    return EXIT_SUCCESS;
}
