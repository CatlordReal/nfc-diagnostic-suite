#include "../diag_ui.h"
#include "../diag_feedback.h"
#include <assets_icons.h>
#include <gui/elements.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t test_free_heap = 65536u, test_max_block = 65536u;
static unsigned detail_allocations, detail_frees, live_details;
static bool fail_allocation, forbid_allocation;
size_t diag_ui_host_free_heap(void) {return test_free_heap;}
size_t diag_ui_host_max_free_block(void) {return test_max_block;}
void* diag_ui_host_alloc(size_t size) {
    assert(!forbid_allocation && !live_details && size <= DIAG_UI_DETAIL_TEXT_LIMIT + 1u);
    ++detail_allocations;
    if(fail_allocation) return NULL;
    void* pointer = malloc(size);
    assert(pointer);
    ++live_details;
    return pointer;
}
void diag_ui_host_free(void* pointer) {
    assert(pointer && live_details);
    ++detail_frees; --live_details; free(pointer);
}
void notification_message(NotificationApp* notification, const NotificationSequence* sequence) {
    assert(!"Renderer must not play notification sequences");
}
static unsigned button_calls[3];
static bool record_step_body;
static unsigned step_body_count;
static char step_body[3][22];
void native_elements_button_left(Canvas* canvas, const char* text);
void native_elements_button_center(Canvas* canvas, const char* text);
void native_elements_button_right(Canvas* canvas, const char* text);
void elements_button_left(Canvas* canvas, const char* text) {
    ++button_calls[0]; native_elements_button_left(canvas, text);
}
void elements_button_center(Canvas* canvas, const char* text) {
    ++button_calls[1]; native_elements_button_center(canvas, text);
}
void elements_button_right(Canvas* canvas, const char* text) {
    ++button_calls[2]; native_elements_button_right(canvas, text);
}
size_t canvas_width(const Canvas* canvas) {return 128;}
size_t canvas_height(const Canvas* canvas) {return 64;}
void canvas_invert_color(Canvas* canvas) {u8g2_SetDrawColor(canvas, !u8g2_GetDrawColor(canvas));}
int canvas_string_width(Canvas* canvas, const char* text) {return u8g2_GetStrWidth(canvas, text);}
void canvas_clear(Canvas* canvas) {memset(canvas->tile_buf_ptr, 0, 1024);}
void canvas_set_color(Canvas* canvas, Color color) {u8g2_SetDrawColor(canvas, color == ColorBlack ? 1 : 0);}
void canvas_set_font(Canvas* canvas, Font font) {
    u8g2_SetFontMode(canvas, 1);
    u8g2_SetFont(canvas, font == FontKeyboard ? u8g2_font_profont11_mr : u8g2_font_haxrcorp4089_tr);
}
void canvas_draw_str(Canvas* canvas, int x, int y, const char* text) {
    if(record_step_body && x == 63 && (y == 27 || y == 37 || y == 47)) {
        assert(step_body_count < 3);
        snprintf(step_body[step_body_count++], sizeof(step_body[0]), "%s", text);
    }
    u8g2_DrawStr(canvas, x, y, text);
}
void canvas_draw_line(Canvas* canvas, int x, int y, int x2, int y2) {u8g2_DrawLine(canvas, x, y, x2, y2);}
void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height) {u8g2_DrawBox(canvas, x, y, width, height);}
void canvas_draw_icon(Canvas* canvas, int x, int y, const Icon* icon) {
    u8g2_DrawXBM(canvas, x, y, icon->width, icon->height, icon->bitmap);
}
static const u8x8_display_info_t display_info = {.tile_width=16,.tile_height=8,.pixel_width=128,.pixel_height=64};
static void capture(Canvas* canvas, DiagUi* ui, const char* directory, const char* name) {
    memset(button_calls, 0, sizeof(button_calls));
    diag_ui_draw(canvas, ui);
    assert(button_calls[0] == (unsigned)(ui->step && ui->left[0]));
    assert(button_calls[1] == (unsigned)(ui->step && ui->center[0]));
    assert(button_calls[2] == (unsigned)(ui->step && ui->right[0]));
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
static void test_detail_lifecycle(Canvas* canvas, DiagUi* ui, const char* directory) {
    char detail[DIAG_UI_DETAIL_TEXT_LIMIT + 1u];
    memset(detail, 'x', sizeof(detail) - 1u);
    memcpy(detail + DIAG_UI_DETAIL_TEXT_LIMIT - 13u, "\nFinal detail", 14u);
    assert(strlen(detail) == DIAG_UI_DETAIL_TEXT_LIMIT);
    char medium[301]; memset(medium, 'm', sizeof(medium) - 1u); medium[300] = '\0';
    diag_ui_text(ui, "Medium", medium, false);
    assert(ui->detail_text && ui->detail_capacity == sizeof(medium));
    diag_ui_text(ui, "Long details", detail, false);
    assert(ui->detail_text && ui->detail_capacity == sizeof(detail));
    assert(!strcmp(ui->detail_text, detail) && live_details == 1u);
    const unsigned allocations = detail_allocations;
    forbid_allocation = true;
    for(size_t index = 0; index < ui->line_count; ++index) diag_ui_move(ui, 1);
    capture(canvas, ui, directory, "details-last");
    assert(detail_allocations == allocations);
    forbid_allocation = false;
    diag_ui_prepare_radio(ui);
    assert(!ui->detail_text && !ui->detail_capacity && !live_details && ui->line_count == 1u);
    diag_ui_prepare_radio(ui);
    diag_ui_text(ui, "Long details", detail, false);
    assert(live_details == 1u);
    diag_ui_text(ui, "Short", "Small detail", false);
    assert(!live_details && !ui->detail_text && !strcmp(ui->text, "Small detail"));
    test_free_heap = 1u;
    diag_ui_text(ui, "Low memory", detail, false);
    assert(!live_details && strstr(ui->text, "Low memory"));
    capture(canvas, ui, directory, "details-low-memory");
    test_free_heap = 65536u; test_max_block = 1u;
    diag_ui_text(ui, "Fragmented", detail, false);
    assert(!live_details && strstr(ui->text, "Low memory"));
    test_max_block = 65536u; fail_allocation = true;
    diag_ui_text(ui, "Alloc failed", detail, false);
    assert(!live_details && strstr(ui->text, "Low memory"));
    fail_allocation = false; forbid_allocation = true; ui->scanning = true;
    diag_ui_text(ui, "Radio active", detail, false);
    assert(!live_details && strstr(ui->text, "shortened"));
    diag_ui_step(ui, "Step", detail, DiagUiArtNone, "", "Done", "");
    assert(!live_details && strstr(ui->text, "shortened"));
    forbid_allocation = false; ui->scanning = false;
    diag_ui_text(ui, "Long details", detail, false);
    assert(live_details == 1u);
    forbid_allocation = true;
    diag_ui_logs(ui, NULL, false, false);
    assert(!live_details && !ui->detail_text);
    forbid_allocation = false;
    char oversized[DIAG_UI_DETAIL_TEXT_LIMIT + 30u];
    memset(oversized, 'z', sizeof(oversized) - 1u); oversized[sizeof(oversized) - 1u] = '\0';
    diag_ui_text(ui, "Bounded", oversized, false);
    assert(ui->detail_text && strlen(ui->detail_text) == DIAG_UI_DETAIL_TEXT_LIMIT);
    assert(strstr(ui->detail_text, "[Text truncated]"));
    diag_ui_menu(ui, "Home", NULL, 0);
    assert(!live_details);
    diag_ui_text(ui, "Long details", detail, false);
    diag_ui_free(ui); diag_ui_free(ui); diag_ui_free(NULL);
    assert(!live_details && detail_allocations == detail_frees + 1u); /* One injected allocation failure. */
}

int main(int argc, char** argv) {
    assert(argc == 2);
    assert(sizeof(DiagUi) <= 416u);
    Canvas canvas = {0};
    uint8_t buffer[1024] = {0};
    canvas.u8x8.display_info = &display_info;
    u8g2_SetupBuffer(&canvas, buffer, 8, u8g2_ll_hvline_vertical_top_lsb, U8G2_R0);
    DiagUi ui = {0};
    test_detail_lifecycle(&canvas, &ui, argv[1]);
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
    diag_ui_menu(&ui, "Sessions", diag_session_menu_items, 8);
    capture(&canvas, &ui, argv[1], "session-menu");
    diag_ui_move(&ui, -1);
    assert(ui.selected == 7u);
    capture(&canvas, &ui, argv[1], "session-menu-bottom");
    diag_ui_menu(&ui, "Reader tests", diag_reader_menu_items, 6);
    capture(&canvas, &ui, argv[1], "reader-menu");
    test_text_and_logs(&canvas, &ui, argv[1]);
    diag_ui_step(&ui, "Read card", "Hold card nearby.\nNFC / LF auto", DiagUiArtCard, "File", "Read", "Tools");
    capture(&canvas, &ui, argv[1], "card-ready");
    diag_ui_step(&ui, "Test reader", "Hold near reader.\nNFC / LF fields", DiagUiArtReader, "", "Scan", "Tools");
    capture(&canvas, &ui, argv[1], "reader-ready");
    diag_ui_step(&ui, "Reading", "NFC\nIdentity read", DiagUiArtScanning, "File", "RFID", "Log");
    for(unsigned frame = 0; frame < 16; ++frame) {
        char name[32];
        ui.animation_frame = frame * 3u;
        snprintf(name, sizeof(name), "busy-%u", frame);
        capture(&canvas, &ui, argv[1], name);
    }
    diag_ui_step(&ui, "Reading", "125 kHz RFID\nScan started", DiagUiArtScanning, "File", "", "Log");
    capture(&canvas, &ui, argv[1], "busy-lf");
    diag_ui_step(&ui, "Reading", "Reader\nScan started", DiagUiArtScanning, "", "", "Log");
    capture(&canvas, &ui, argv[1], "busy-reader");
    diag_ui_step(&ui, "Reading", "Reader\nScan started", DiagUiArtScanning, "", "RFID", "Log");
    capture(&canvas, &ui, argv[1], "busy-nfc-reader");
    diag_ui_step(&ui, "Stopping", "NFC\nIdentity read", DiagUiArtScanning, "", "", "Log");
    capture(&canvas, &ui, argv[1], "busy-stopping");
    diag_ui_step(&ui, "Card inspected", "Ultralight/NTAG2xx\nCommand confirmed\n04A1B2C3D4E5F6", DiagUiArtNone, "File", "Save", "Tools");
    capture(&canvas, &ui, argv[1], "card-outcome");
    diag_ui_step(&ui, "Reader fields", "NFC: yes  LF: no\nField observation\nType not identified", DiagUiArtNone, "", "Save", "Tests");
    capture(&canvas, &ui, argv[1], "reader-fields");
    diag_ui_step(&ui, "Report saved", "Ungrouped", DiagUiArtSuccess, "", "Done", "Tools");
    capture(&canvas, &ui, argv[1], "saved-step");
    diag_ui_step(&ui, "Report saved", "a aaaaaaaaaaaaaaaaaaaaaa", DiagUiArtSuccess, "", "Done", "Tools");
    record_step_body = true;
    capture(&canvas, &ui, argv[1], "saved-system-long");
    record_step_body = false;
    assert(step_body_count == 3 && !strcmp(step_body[0], "a") && !strcmp(step_body[1], "aaaaaaaaaaaa") && !strcmp(step_body[2], "aaaaaaaaaa"));
    diag_ui_step(&ui, "Check saved copy", "Read blank to a\nNEW file, then\ncompare here.", DiagUiArtCard, "", "Check", "Tools");
    capture(&canvas, &ui, argv[1], "verify-copy");
    diag_ui_step(&ui, "Read card", "Select saved card\nto continue.", DiagUiArtCard, "", "File", "Tools");
    capture(&canvas, &ui, argv[1], "choose-file");
    diag_ui_step(&ui, "Re-read original", "Read original\nwith recovered\nkeys; save file.", DiagUiArtCard, "File", "Read", "Tools");
    capture(&canvas, &ui, argv[1], "reread");
    diag_ui_step(&ui, "Save failed", "SD card\nnot ready", DiagUiArtError, "File", "Retry", "Log");
    capture(&canvas, &ui, argv[1], "error-step");
    DiagReaderStats nonces = {.mode = DiagReaderModeClassic, .transcripts_collected = 1};
    char nonce_body[96];
    diag_nonce_readiness_text(&nonces, true, nonce_body, sizeof(nonce_body));
    diag_ui_step(&ui, "Reader nonces", nonce_body, DiagUiArtNone, "", "Done", "Log");
    ui.scanning = true;
    capture(&canvas, &ui, argv[1], "nonces-waiting");
    nonces.transcripts_collected = 2; nonces.nonce_pairs = 1;
    diag_nonce_readiness_text(&nonces, true, nonce_body, sizeof(nonce_body));
    diag_ui_step(&ui, "Reader nonces", nonce_body, DiagUiArtNone, "", "Done", "Log");
    ui.scanning = true;
    capture(&canvas, &ui, argv[1], "nonces-pair");
    nonces.pairs_saved = 1;
    diag_nonce_readiness_text(&nonces, false, nonce_body, sizeof(nonce_body));
    diag_ui_step(&ui, "Reader nonces", nonce_body, DiagUiArtNone, "", "Decode", "Tools");
    capture(&canvas, &ui, argv[1], "nonces-saved");
    diag_ui_step(&ui, "No actions", "No blank buttons", DiagUiArtNone, NULL, "", NULL);
    capture(&canvas, &ui, argv[1], "no-actions");
    diag_ui_step(&ui, "Open native tool", "Ready", DiagUiArtCard, NULL, "Open", "Cancel");
    capture(&canvas, &ui, argv[1], "open-tool");
    /* Native button geometry, including three-pixel angled edges, must fit. */
    canvas_set_font(&canvas, FontSecondary);
    const int left_end = canvas_string_width(&canvas, "File") + 16;
    const int center_width = canvas_string_width(&canvas, "Check") + 12;
    const int center_start = (128 - center_width) / 2;
    const int right_start = 128 - canvas_string_width(&canvas, "Tools") - 16;
    assert(left_end < center_start - 3);
    assert(center_start + center_width + 3 < right_start);
    const int decode_width = canvas_string_width(&canvas, "Decode") + 12;
    assert((128 - decode_width) / 2 + decode_width + 3 < right_start);
    diag_ui_free(&ui);
    assert(!live_details);
    printf("UI renderer, virtual log, wrap checks passed; DiagUi host=%zu bytes\n", sizeof(ui));
    return EXIT_SUCCESS;
}
