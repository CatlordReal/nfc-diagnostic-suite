#pragma once
#include "u8g2.h"
typedef u8g2_t Canvas;
typedef enum {ColorWhite, ColorBlack} Color;
typedef enum {FontPrimary, FontSecondary, FontKeyboard} Font;
void canvas_clear(Canvas* canvas);
void canvas_set_color(Canvas* canvas, Color color);
void canvas_set_font(Canvas* canvas, Font font);
void canvas_draw_str(Canvas* canvas, int x, int y, const char* text);
void canvas_draw_line(Canvas* canvas, int x1, int y1, int x2, int y2);
void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height);

int canvas_string_width(Canvas* canvas, const char* text);
