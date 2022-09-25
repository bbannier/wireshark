#include "config.h"
#include "epan/packet.h"

#include <gmodule.h>

#include <epan/epan.h>
#include <epan/proto.h>
#include <ws_diag_control.h>
#include <wsutil/filesystem.h>
#include <wsutil/plugins.h>
#include <wsutil/report_message.h>
#include <wsutil/ws_assert.h>
#include <wsutil/wslog.h>

#include <stdio.h>
#include <string.h>

/* Helper function to get the location of Spicy JIT related files. */
gchar *spicy_jit_dir(void) {
  const gchar *dirpath = get_plugins_pers_dir_with_version();
  return g_build_filename(dirpath, "spicy-jit", (gchar *)NULL);
}

/*
 * Finds the only public parser in `source` or NULL if not exactly one is found.
 */
gchar *parser_name(gchar *filename) {
  char *source;
  gsize source_len;
  GError *err = NULL;
  if (!g_file_get_contents(filename, &source, &source_len, &err))
    ws_info("Could not read file \"%s\": %s", filename, err->message);

  char **lines = g_strsplit(source, "\n", 0);
  gchar *module = NULL;
  gchar *parser = NULL;
  for (size_t j = 0; lines[j] != NULL; ++j) {
    /* Extract parser name. */
    if (strncmp(lines[j], "public", strlen("public")) == 0) {
      if (parser) {
        ws_info("File \"%s\" contains more than one public type", filename);
        return false;
      }

      char **tokens = g_strsplit(lines[j], " ", 4);
      parser = g_strdup(tokens[2]);
      g_strfreev(tokens);
    }
    /* Extract module name. */
    else if (strncmp(lines[j], "module", strlen("module")) == 0) {
      char **tokens1 = g_strsplit(lines[j], " ", 2);
      module = tokens1[1];

      /* Strip off any trailing characters. */
      if (module) {
        char **tokens2 = g_strsplit(module, ";", 2);
        module = g_strdup(tokens2[0]);
        g_strfreev(tokens2);
      }

      g_strfreev(tokens1);
    }
  }
  g_strfreev(lines);

  gchar *parser_name = NULL;

  if (module && parser)
    parser_name = g_strconcat(module, "::", parser, NULL);

  g_free(module);
  g_free(parser);

  return parser_name;
}

/* Load JIT'ed Spicy library. */
void load_compiled(gchar *name) {
  GModule *handle = g_module_open(name, G_MODULE_BIND_LOCAL);
  if (!handle) {
    ws_info("Failed to load Spicy module \"%s\"", name);
    g_module_close(handle);
  }

  gpointer symbol;

  /* Search for the entry point for the plugin registration function */
  bool register_found = g_module_symbol(handle, "plugin_register", &symbol);
  g_assert(register_found);

  DIAG_OFF_PEDANTIC
      /* Found it, call the plugin registration function. */
      ((plugin_register_func)symbol)();
  DIAG_ON_PEDANTIC
}

gchar *jit(gchar *filename) {
  /* JIT the file. */
  gchar *jitdir = spicy_jit_dir();
  gchar *helper = g_build_filename(jitdir, "make_plugin.py", NULL);

  gchar *parser = parser_name(filename);
  ws_info("Generating dissector for Spicy unit %s from \"%s\"", parser,
          filename);

  char plugin_want_major[10];
  snprintf(plugin_want_major, 10, "%d", VERSION_MAJOR);
  char plugin_want_minor[10];
  snprintf(plugin_want_minor, 10, "%d", VERSION_MINOR);

  gchar *output = g_strconcat(filename, ".so", NULL);
  gchar *wireshark_include_dir = g_strdup(g_getenv("WIRESHARK_INCLUDE_DIR"));
  ws_assert(wireshark_include_dir);

  gchar *wireshark_lib_dir = g_strdup(g_getenv("WIRESHARK_LIB_DIR"));
  ws_assert(wireshark_lib_dir);

  gchar *stderr[1024] = {0};

  GError *err = NULL;

  gchar *argv[] = {helper,
                   "--parser",
                   parser,
                   "--plugin_version",
                   "0.0.0",
                   "--plugin_want_major",
                   plugin_want_major,
                   "--plugin_want_minor",
                   plugin_want_minor,
                   "--wireshark_include_dir",
                   wireshark_include_dir,
                   "--wireshark_library_dir",
                   wireshark_lib_dir,
                   "--output",
                   output,
                   filename};
  g_spawn_sync(jitdir, argv, (gchar **)NULL, G_SPAWN_DEFAULT, NULL, NULL, NULL,
               stderr, NULL, &err);

  if (err) {
    ws_info("Failed to jit Spicy file \"%s\": %s", filename, err->message);

    for (size_t i = 0; stderr[i] != NULL; ++i)
      ws_info("Spicy JIT: %s", stderr[i]);
  }

  g_free(wireshark_include_dir);
  g_free(parser);
  g_free(helper);
  g_free(jitdir);

  return output;
}

/* Load the given Spicy file into Wireshark. */
void load_spicy(gchar *filename) {
  ws_info("Loading %s", filename);

  gchar *output = jit(filename);
  if (!output)
    return;

  load_compiled(output);
  g_free(output);
}

void proto_register_spicy_jit(void) {
  gchar *jitdir = spicy_jit_dir();

  GDir *dir = g_dir_open(jitdir, 0, NULL);
  if (dir == NULL) {
    g_free(jitdir);
    return;
  }

  const char *name;
  while ((name = g_dir_read_name(dir)) != NULL) {
    /* We only work on Spicy files. */
    if (!g_str_has_suffix(name, ".spicy"))
      continue;

    gchar *filename = g_build_filename(jitdir, name, (gchar *)NULL);
    load_spicy(filename);
    g_free(filename);
  }

  g_free(jitdir);
}

static int dissect_dummy(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree _U_, void *data _U_) {
  (void)tvb;
  (void)pinfo;
  return 0;
}

/* This plugin registers no dissector. */
void proto_reg_handoff_spicy_jit(void) {
  static dissector_handle_t dummy_handle;
  dummy_handle = create_dissector_handle(dissect_dummy, -1);
  (void)dummy_handle;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
