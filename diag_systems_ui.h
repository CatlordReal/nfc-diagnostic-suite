#ifndef DIAG_SYSTEMS_UI_H
#define DIAG_SYSTEMS_UI_H

#include "diag_systems.h"

typedef struct Gui Gui;

/* Caller pauses its viewport and drains input before and after this modal helper. */
bool diag_system_choose(
    Storage* storage,
    Gui* gui,
    char name[DIAG_SYSTEM_NAME_CAPACITY],
    FuriString* explanation);

#endif
