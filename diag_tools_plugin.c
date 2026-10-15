#include "diag_tools_plugin.h"

#include <flipper_application/flipper_application.h>

const FlipperAppPluginDescriptor* diag_tools_plugin_ep(void);

static const DiagToolsApi diag_tools_api_table = {
    .recommend = diag_insights_recommend,
    .from_reader = diag_reader_fingerprint_from_reader,
    .from_fields = diag_reader_fingerprint_from_fields,
    .resolve_directory = diag_system_resolve_directory,
    .current_load = diag_system_current_load,
    .save_reader_profile = diag_system_save_reader_profile,
    .find_similar = diag_system_find_similar,
    .choose = diag_system_choose,
};

static const FlipperAppPluginDescriptor diag_tools_descriptor = {
    .appid = DIAG_TOOLS_PLUGIN_APP_ID,
    .ep_api_version = DIAG_TOOLS_PLUGIN_API_VERSION,
    .entry_point = &diag_tools_api_table,
};

const FlipperAppPluginDescriptor* diag_tools_plugin_ep(void) {
    return &diag_tools_descriptor;
}
