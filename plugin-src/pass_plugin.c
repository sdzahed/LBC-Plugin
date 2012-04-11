/* A trivial (dumb) plugin example that shows how to use the GCC plugin
   mechanism.  */

#include "gcc-plugin.h"
#include <stdlib.h>
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tree.h"
#include "tree-pass.h"
#include "intl.h"
#include "toplev.h"
#include "diagnostic.h"

int plugin_is_GPL_compatible;

void
handle_init (void *event_data, void *data)
{
    tree glob = NULL_TREE;
    if (current_function_decl == NULL_TREE)
        printf("It is null\n");
    else
        glob = DECL_CONTEXT(current_function_decl);

    if (glob != NULL_TREE && TREE_CODE(glob) == TRANSLATION_UNIT_DECL)
    {
        printf("Found it in %s\n", IDENTIFIER_POINTER(DECL_NAME(current_function_decl)));
        tree decl = BLOCK_VARS(DECL_INITIAL(glob));
        while (decl != NULL_TREE) {
            if (TREE_CODE(decl) == VAR_DECL){
                const char *var_name = IDENTIFIER_POINTER(DECL_NAME(decl));
                printf("Glob var: %s decl_external:%d tree_static:%d complete:%d common: %d\n", var_name, \
                        DECL_EXTERNAL(decl), TREE_STATIC(decl), COMPLETE_TYPE_P(decl), DECL_COMMON(decl));
                debug_tree(decl);
            }
            decl = DECL_CHAIN(decl);
        }
    }
}

void
handle_new_passes (void *event_data, void *data)
{
  struct opt_pass *pass = (struct opt_pass *)event_data;
  printf ("Executing pass = %s \n", pass->name);
}

/* Initialization function that GCC calls. This plugin takes an argument
   that specifies the name of the reference pass and an instance number,
   both of which determine where the plugin pass should be inserted.  */

int
plugin_init (struct plugin_name_args *plugin_info,
             struct plugin_gcc_version *version)
{
  const char *plugin_name = plugin_info->base_name;
  int argc = plugin_info->argc;
  struct plugin_argument *argv = plugin_info->argv;
  int i;

  /* Process the plugin arguments. This plugin takes the following arguments:
     ref-pass-name=<PASS_NAME> and ref-pass-instance-num=<NUM>.  */
  for (i = 0; i < argc; ++i)
    {
        warning (0, G_("plugin %qs: argument %qs value %qs"),
                 plugin_name, argv[i].key, argv[i].value);
    }

  //register_callback (plugin_name, PLUGIN_START_UNIT, handle_init, NULL);
  register_callback (plugin_name, PLUGIN_ALL_PASSES_START, handle_init, NULL);
  //register_callback (plugin_name, PLUGIN_PASS_EXECUTION, handle_new_passes, NULL);

  return 0;
}
