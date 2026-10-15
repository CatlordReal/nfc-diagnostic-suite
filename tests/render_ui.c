#include "../diag_ui.h"
#include "../diag_capabilities.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int canvas_string_width(Canvas* c, const char* text) {return u8g2_GetStrWidth(c,text);}
void canvas_clear(Canvas* c) { memset(c->tile_buf_ptr, 0, 1024); }
void canvas_set_color(Canvas* c, Color color) {u8g2_SetDrawColor(c, color == ColorBlack ? 1 : 0);}
void canvas_set_font(Canvas* c, Font font) {
    u8g2_SetFontMode(c, 1);
    u8g2_SetFont(c, font == FontKeyboard ? u8g2_font_profont11_mr : u8g2_font_haxrcorp4089_tr);
}
void canvas_draw_str(Canvas* c, int x, int y, const char* text) {u8g2_DrawStr(c,x,y,text);}
void canvas_draw_line(Canvas* c,int x,int y,int x2,int y2) {u8g2_DrawLine(c,x,y,x2,y2);}
void canvas_draw_box(Canvas* c,int x,int y,int w,int h) {u8g2_DrawBox(c,x,y,w,h);}
static const u8x8_display_info_t display_info = {.tile_width=16,.tile_height=8,.pixel_width=128,.pixel_height=64};
static void capture(Canvas* canvas, DiagUi* ui, const char* directory, const char* name) {
    diag_ui_draw(canvas, ui);
    char path[512];snprintf(path,sizeof(path),"%s/%s.pbm",directory,name);
    FILE* file=fopen(path,"wb");assert(file);
    fputs("P1\n128 64\n",file);
    for(int y=0;y<64;y++) {for(int x=0;x<128;x++) fprintf(file,"%u%s",(canvas->tile_buf_ptr[(y/8)*128+x]>>(y%8))&1,x==127?"":" ");fputc('\n',file);}
    assert(!fclose(file));
}
int main(int argc,char**argv) {
    assert(argc==2);
    Canvas canvas={0};uint8_t buffer[1024]={0};
    canvas.u8x8.display_info=&display_info;
    u8g2_SetupBuffer(&canvas,buffer,8,u8g2_ll_hvline_vertical_top_lsb,U8G2_R0);
    DiagUi* ui=calloc(1,sizeof(*ui));assert(ui);
    ui->menu=true;capture(&canvas,ui,argv[1],"menu");
    ui->selected=9;capture(&canvas,ui,argv[1],"tools");
    diag_ui_text(ui,"Results","Simulation\n2026-10-15T18:30:00\nInspection complete\nUID (API byte order):\n04 A1 B2 C3 D4 E5 F6\nATQA: 00 44 (MSB)\nSAK: 00 (final)\nCascade levels: 2\nDerived from UID size.\nCandidate only",false);
    capture(&canvas,ui,argv[1],"results");
    for(int i=0;i<5;i++)diag_ui_move(ui,1);
    capture(&canvas,ui,argv[1],"identity");
    diag_ui_text(ui,"Live log","0 ms Info\nNFC resource acquired\n125 ms Success\nISO14443-A selected\n160 ms Info\nGET_VERSION requested\n190 ms Warning\nVersion not supported\nCommand response only\nNo family confirmation",false);
    ui->scanning=true;ui->run_number=2;
    capture(&canvas,ui,argv[1],"log");
    for(int i=0;i<4;i++) {diag_ui_move(ui,1);char name[32];snprintf(name,sizeof(name),"log-%d",i);capture(&canvas,ui,argv[1],name);}
    ui->run_number=0;
    for(unsigned frame=0;frame<16;frame++) {
        ui->animation_frame=frame*3;
        char name[32];snprintf(name,sizeof(name),"busy-%u",frame);
        capture(&canvas,ui,argv[1],name);
    }
    ui->scanning=false;
    diag_ui_text(ui,"Diagnose","Last successful stage:\nIdentity read\nError: ISO14443-3A\nCode: 7\nReposition card; retry\nwith one tag present.\nLikely causes only;\nnot measurements.",false);
    capture(&canvas,ui,argv[1],"diagnose");
    assert(ui->line_count>5);for(int i=0;i<100;i++)diag_ui_move(ui,1);assert(ui->scroll==ui->line_count-5);
    for(int i=0;i<100;i++)diag_ui_move(ui,-1);assert(ui->scroll==0);
    diag_ui_menu(ui,"Reader diagnostics",diag_reader_menu_items,6);
    ui->selected=3;capture(&canvas,ui,argv[1],"reader-menu");
    diag_ui_menu(ui,"Card workflow",diag_workflow_start_items,3);
    capture(&canvas,ui,argv[1],"workflow-start");
    unsigned actions[16];const char* labels[16];
    DiagCapabilities lf={.has_identity=true,.is_lf=true,.can_native_write=true};
    size_t count=diag_capabilities_workflow_actions(lf,2,true,true,false,actions,16);
    for(size_t i=0;i<count;i++)labels[i]=diag_workflow_menu_items[actions[i]];
    diag_ui_menu(ui,"Card workflow",labels,count);ui->selected=5;
    capture(&canvas,ui,argv[1],"workflow-lf");
    for(int i=0;i<100;i++)diag_ui_move(ui,1);assert(ui->selected==count-1);
    DiagCapabilities classic={.has_identity=true,.is_nfc=true,.classic=true,.can_magic_write=true};
    count=diag_capabilities_workflow_actions(classic,1,true,true,true,actions,16);
    for(size_t i=0;i<count;i++)labels[i]=diag_workflow_menu_items[actions[i]];
    diag_ui_menu(ui,"Card workflow",labels,count);ui->selected=6;
    capture(&canvas,ui,argv[1],"workflow-classic");
    diag_ui_text(ui,"125 kHz results","Simulation\nNative LF decode\nHIDProx\nDecoded data:\n20 01 23 45 67 89\nCandidate is not proof.\nNo reader identified.",false);
    capture(&canvas,ui,argv[1],"lf-results");
    diag_ui_text(ui,"Reader report","Simulation\nNFC field monitor\nSamples: 3000\nPeriod: 10 ms\nOn/off edges: 3/2\nSampled durations only.\nNo brand/strength claim.",false);
    capture(&canvas,ui,argv[1],"reader-report");
    free(ui);puts("UI renderer and navigation checks passed");return 0;
}
