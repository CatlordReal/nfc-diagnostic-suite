#ifndef DIAG_TOOLS_LOADER_H
#define DIAG_TOOLS_LOADER_H

#include "diag_tools_plugin.h"

typedef struct DiagTools DiagTools;

/* Loads only the suite's embedded offline-tools FAL. No radio may be active.
   API pointers and returned static strings become invalid after close. */
DiagTools* diag_tools_open(Storage* storage, FuriString* explanation);
const DiagToolsApi* diag_tools_api(DiagTools* tools);
void diag_tools_close(DiagTools* tools);

#endif
