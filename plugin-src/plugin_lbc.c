/* Mudflap: narrow-pointer bounds-checking by tree rewriting.
   Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
   Free Software Foundation, Inc.
   Contributed by Frank Ch. Eigler <fche@redhat.com>
   and Graydon Hoare <graydon@redhat.com>

This file is part of GCC.

GCC is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

GCC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with GCC; see the file COPYING3.  If not see
<http://www.gnu.org/licenses/>.  */

#include <stdio.h>
#include "gcc-plugin.h"
#include "plugin-version.h"
#include "config.h"
#include "system.h"
#include "coretypes.h"
#include "tm.h"
#include "tree.h"
#include "tm_p.h"
#include "basic-block.h"
#include "flags.h"
#include "function.h"
#include "tree-inline.h"
#include "gimple.h"
#include "tree-iterator.h"
#include "tree-flow.h"
#include "plugin_lbc.h"
#include "tree-dump.h"
#include "tree-pass.h"
#include "hashtab.h"
#include "intl.h"
#include "toplev.h"
#include "diagnostic.h"
#include "demangle.h"
#include "langhooks.h"
#include "ggc.h"
#include "cgraph.h"
#include "gimple.h"
#include "Judy.h"

int plugin_is_GPL_compatible;

/* Internal function decls */


/* Options.  */
#define flag_mudflap_threads (flag_mudflap == 2)

/* Helpers.  */
static tree mf_build_string (const char *string);
static char* mf_varname_tree (tree);

void execute_lbc_init (void *event_data, void *data);

/* Indirection-related instrumentation.  */
static void mf_xform_statements (void);
static unsigned int execute_mudflap_function_ops (void);

/* Addressable variables instrumentation.  */
static void mf_xform_decls (gimple_seq, tree);
static tree mx_xfn_xform_decls (gimple_stmt_iterator *, bool *,
				struct walk_stmt_info *);
static gimple_seq mx_register_decls (tree, gimple_seq, gimple, location_t, bool);
static unsigned int execute_mudflap_function_decls (void);
static tree create_struct_type(tree decl, size_t front_rz_size, size_t rear_rz_size);
static tree mx_xform_instrument_pass2(tree temp);

/* Hash map to store instrumented var_decl nodes */
Pvoid_t decl_map;

/* ------------------------------------------------------------------------ */
/* Some generally helpful functions for mudflap instrumentation.  */

/* Build a reference to a literal string.  */
static tree
mf_build_string (const char *string)
{
  size_t len = strlen (string);
  tree result = mf_mark (build_string (len + 1, string));

  TREE_TYPE (result) = build_array_type
    (char_type_node, build_index_type (build_int_cst (NULL_TREE, len)));
  TREE_CONSTANT (result) = 1;
  TREE_READONLY (result) = 1;
  TREE_STATIC (result) = 1;

  result = build1 (ADDR_EXPR, build_pointer_type (char_type_node), result);

  return mf_mark (result);
}

/* Create a properly typed STRING_CST node that describes the given
   declaration.  It will be used as an argument for __mf_register().
   Try to construct a helpful string, including file/function/variable
   name.  */

static char * 
mf_varname_tree (tree decl)
{
	static pretty_printer buf_rec;
	static int initialized = 0;
	pretty_printer *buf = & buf_rec;
	char *buf_contents;
	tree result;

	gcc_assert (decl);

	if (!initialized)
	{
		pp_construct (buf, /* prefix */ NULL, /* line-width */ 0);
		initialized = 1;
	}
	pp_clear_output_area (buf);

	/* Add FILENAME[:LINENUMBER[:COLUMNNUMBER]].  */
	{
		expanded_location xloc = expand_location (DECL_SOURCE_LOCATION (decl));
		const char *sourcefile;
		unsigned sourceline = xloc.line;
		unsigned sourcecolumn = 0;
		sourcecolumn = xloc.column;
		sourcefile = xloc.file;
		if (sourcefile == NULL && current_function_decl != NULL_TREE)
			sourcefile = DECL_SOURCE_FILE (current_function_decl);
		if (sourcefile == NULL)
			sourcefile = "<unknown file>";

		pp_string (buf, sourcefile);

		if (sourceline != 0)
		{
			pp_string (buf, ":");
			pp_decimal_int (buf, sourceline);

			if (sourcecolumn != 0)
			{
				pp_string (buf, ":");
				pp_decimal_int (buf, sourcecolumn);
			}
		}
	}

	if (current_function_decl != NULL_TREE)
	{
		/* Add (FUNCTION) */
		pp_string (buf, " (");
		{
			const char *funcname = NULL;
			if (DECL_NAME (current_function_decl))
				funcname = lang_hooks.decl_printable_name (current_function_decl, 1);
			if (funcname == NULL)
				funcname = "anonymous fn";

			pp_string (buf, funcname);
		}
		pp_string (buf, ") ");
	}
	else
		pp_string (buf, " ");

	/* Add <variable-declaration>, possibly demangled.  */
	{
		const char *declname = NULL;

		if (DECL_NAME (decl) != NULL)
		{
			if (strcmp ("GNU C++", lang_hooks.name) == 0)
			{
				/* The gcc/cp decl_printable_name hook doesn't do as good a job as
				   the libiberty demangler.  */
				declname = cplus_demangle (IDENTIFIER_POINTER (DECL_NAME (decl)),
						DMGL_AUTO | DMGL_VERBOSE);
			}
			if (declname == NULL)
				declname = lang_hooks.decl_printable_name (decl, 3);
		}
		if (declname == NULL)
			declname = "<unnamed variable>";

		pp_string (buf, declname);
	}

	/* Return the lot as a new STRING_CST.  */
	buf_contents = pp_base_formatted_text (buf);
	//DEBUGLOG("buf_contents : %s\n", buf_contents);
	result = mf_build_string (buf_contents);
	pp_clear_output_area (buf);

	//  return result;
	return buf_contents;
}



/* global tree nodes */

/* uintptr_t (usually "unsigned long") */
static GTY (()) tree mf_uintptr_type;

/* LBC related function delcarations */

/* void init_front_redzone (void* front_rz, unsigned front_rz_size); */
static GTY (()) tree lbc_init_front_rz_fndecl;

/* void uninit_front_redzone (void* front_rz, unsigned front_rz_size) */
static GTY (()) tree lbc_uninit_front_rz_fndecl;

/* void init_rear_redzone (void* rear_rz, unsigned rear_rz_size) */
static GTY (()) tree lbc_init_rear_rz_fndecl;

/* void uninit_rear_redzone (void* rear_rz, unsigned rear_rz_size) */
static GTY (()) tree lbc_uninit_rear_rz_fndecl;

/* void ensure_sframe_bitmap() */
static GTY (()) tree lbc_ensure_sframe_bitmap_fndecl;

/* void is_char_red (unsigned int value,unsigned int orig_value_size, const void* ptr)*/
static GTY (()) tree lbc_is_char_red_fndecl;

static GTY (()) tree global_struct_var;

struct htable_entry{
	char name[100];
	tree t_name;
};

/* Helper for mudflap_init: construct a decl with the given category,
   name, and type, mark it an external reference, and pushdecl it.  */
static inline tree
mf_make_builtin (enum tree_code category, const char *name, tree type)
{
  tree decl = mf_mark (build_decl (UNKNOWN_LOCATION,
				   category, get_identifier (name), type));
  TREE_PUBLIC (decl) = 1;
  DECL_EXTERNAL (decl) = 1;
  lang_hooks.decls.pushdecl (decl);
  /* The decl was declared by the compiler.  */
  DECL_ARTIFICIAL (decl) = 1;
  /* And we don't want debug info for it.  */
  DECL_IGNORED_P (decl) = 1;
  return decl;
}

void
execute_lbc_finish (void *event_data, void *data)
{
    DEBUGLOG("Done processing the tranlation unit.\n");
}

void
execute_lbc_init (void *event_data, void *data)
{
    lbc_init();
}

void
lbc_init (void)
{
    static bool done = false;
	tree lbc_init_uninit_rz_fntype;
	tree lbc_ensure_sframe_fntype;
	tree lbc_is_char_red_fntype;
	tree lbc_const_void_ptr_type;

    if (done)
        return;
    done = true;

    decl_map = (Pvoid_t) NULL;

    DEBUGLOG("LBC Plugin: Building decls\n");

	lbc_const_void_ptr_type = build_qualified_type (ptr_type_node, TYPE_QUAL_CONST);

	lbc_init_uninit_rz_fntype =
		build_function_type_list (void_type_node, ptr_type_node,
				unsigned_type_node, NULL_TREE);
	/*lbc_ensure_sframe_fntype =
		build_function_type_list (void_type_node, ptr_type_node,
                ptr_type_node, NULL_TREE);*/
	lbc_ensure_sframe_fntype =
		build_function_type_list (void_type_node, void_type_node, NULL_TREE);

	lbc_is_char_red_fntype =
		build_function_type_list (void_type_node, unsigned_type_node,
				unsigned_type_node, lbc_const_void_ptr_type, NULL_TREE);

	lbc_init_front_rz_fndecl = mf_make_builtin (FUNCTION_DECL, "init_front_redzone",
			lbc_init_uninit_rz_fntype);
	lbc_uninit_front_rz_fndecl = mf_make_builtin (FUNCTION_DECL, "uninit_front_redzone",
			lbc_init_uninit_rz_fntype);
	lbc_init_rear_rz_fndecl = mf_make_builtin (FUNCTION_DECL, "init_rear_redzone",
			lbc_init_uninit_rz_fntype);
	lbc_uninit_rear_rz_fndecl = mf_make_builtin (FUNCTION_DECL, "uninit_rear_redzone",
			lbc_init_uninit_rz_fntype);
	lbc_ensure_sframe_bitmap_fndecl = mf_make_builtin (FUNCTION_DECL, "ensure_sframe_bitmap",
			lbc_ensure_sframe_fntype);
	lbc_is_char_red_fndecl = mf_make_builtin (FUNCTION_DECL, "is_char_red",
			lbc_is_char_red_fntype);
    DEBUGLOG("LBC Plugin: Done Building decls\n");
}

static bool
gate_lbc (void)
{
  return true;
}

struct gimple_opt_pass pass_lbc_1 =
{
 {
  GIMPLE_PASS,
  "lbc1",                           /* name */
  gate_lbc,                         /* gate */
  execute_mudflap_function_decls,       /* execute */
  NULL,                                 /* sub */
  NULL,                                 /* next */
  0,                                    /* static_pass_number */
  TV_NONE,                              /* tv_id */
  PROP_gimple_any,                      /* properties_required */
  //PROP_cfg,                      /* properties_required */
  0,                                    /* properties_provided */
  0,                                    /* properties_destroyed */
  0,                                    /* todo_flags_start */
  TODO_dump_func                        /* todo_flags_finish */
 }
};

struct gimple_opt_pass pass_lbc_2 =
{
 {
  GIMPLE_PASS,
  "lbc2",                           /* name */
  gate_lbc,                         /* gate */
  execute_mudflap_function_ops,         /* execute */
  NULL,                                 /* sub */
  NULL,                                 /* next */
  0,                                    /* static_pass_number */
  TV_NONE,                              /* tv_id */
  PROP_ssa | PROP_cfg | PROP_gimple_leh,/* properties_required */
  0,                                    /* properties_provided */
  0,                                    /* properties_destroyed */
  0,                                    /* todo_flags_start */
  TODO_verify_flow | TODO_verify_stmts
  | TODO_dump_func | TODO_update_ssa    /* todo_flags_finish */
 }
};

/* Initialize the global tree nodes that correspond to mf-runtime.h
   declarations.  */
int
plugin_init (struct plugin_name_args *pinfo,
             struct plugin_gcc_version *version)
{
    struct register_pass_info pass_info1;
    struct register_pass_info pass_info2;
    const char *plugin_name = "LBC";

    struct plugin_info info = {"1.0", "Use -fplugin=path/to/lbc.so to use the lbc plugin"};

    DEBUGLOG("LBC Plugin: Initializing plugin version %s \n", info.version);

    // Check for build time versus run time gcc version
    if (!plugin_default_version_check (version, &gcc_version))
        return 1;

    // Start plugin related work here.
    register_callback (plugin_name, PLUGIN_START_UNIT, execute_lbc_init, NULL);
    register_callback (plugin_name, PLUGIN_FINISH_UNIT, execute_lbc_finish, NULL);

    // TODO for some reason the following call is giving a segfault in GCC code
    //register_callback (plugin_name, PLUGIN_INFO, NULL, &info);

    DEBUGLOG("LBC Plugin: Building pass1\n");
    pass_info1.pass = &pass_lbc_1.pass;
    pass_info1.reference_pass_name = "omplower";
    pass_info1.ref_pass_instance_number = 1;
    pass_info1.pos_op = PASS_POS_INSERT_BEFORE;

    DEBUGLOG("LBC Plugin: Registering pass1\n");
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info1);

    DEBUGLOG("LBC Plugin: Building pass2\n");
    pass_info2.pass = &pass_lbc_2.pass;
    //pass_info2.reference_pass_name = "ssa";
    pass_info2.reference_pass_name = "optimized";
    pass_info2.ref_pass_instance_number = 1;
    pass_info2.pos_op = PASS_POS_INSERT_BEFORE;

    DEBUGLOG("LBC Plugin: Registering pass2\n");
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info2);
    return 0;
}


/* ------------------------------------------------------------------------ */
/* This is the second part of the mudflap instrumentation.  It works on
   low-level GIMPLE using the CFG, because we want to run this pass after
   tree optimizations have been performed, but we have to preserve the CFG
   for expansion from trees to RTL.
   Below is the list of transformations performed on statements in the
   current function.

 1)  Memory reference transforms: Perform the mudflap indirection-related
    tree transforms on memory references.

 2) Mark BUILTIN_ALLOCA calls not inlineable.

 */

static unsigned int execute_mudflap_function_ops (void)
{
	struct gimplify_ctx gctx;
	DEBUGLOG("Zahed: entering LBC pass2\n");
	//return;
	/* Don't instrument functions such as the synthetic constructor
	   built during mudflap_finish_file.  */
	if (mf_marked_p (current_function_decl) ||
			DECL_ARTIFICIAL (current_function_decl))
		return 0;

	push_gimplify_context (&gctx);

	mf_xform_statements ();

	pop_gimplify_context (NULL);
	return 0;
}

/* Check whether the given decl, generally a VAR_DECL or PARM_DECL, is
   eligible for instrumentation.  For the mudflap1 pass, this implies
   that it should be registered with the libmudflap runtime.  For the
   mudflap2 pass this means instrumenting an indirection operation with
   respect to the object.
*/
static int
mf_decl_eligible_p (tree decl)
{
  return ((TREE_CODE (decl) == VAR_DECL || TREE_CODE (decl) == PARM_DECL)
          /* The decl must have its address taken.  In the case of
             arrays, this flag is also set if the indexes are not
             compile-time known valid constants.  */
	  /* XXX: not sufficient: return-by-value structs! */
          && TREE_ADDRESSABLE (decl)
          /* The type of the variable must be complete.  */
          && COMPLETE_OR_VOID_TYPE_P (TREE_TYPE (decl))
	  /* The decl hasn't been decomposed somehow.  */
	  && !DECL_HAS_VALUE_EXPR_P (decl));
}

tree find_instr_node(tree temp)
{
	int ret = 0;
    tree decl_node;
    PWord_t PV;
    JSLG(PV, decl_map, mf_varname_tree(temp));
    if(PV){
        decl_node = ((tree) *PV);
        gcc_assert(decl_node != NULL_TREE);
        DEBUGLOG("[find_instr] Match found for %s --> %s\n",mf_varname_tree(temp), IDENTIFIER_POINTER(DECL_NAME(decl_node)));
        return decl_node;
    }else
        DEBUGLOG("[find_instr] Match not found for %s\n",mf_varname_tree(temp));
    return NULL_TREE;
}

static tree mx_xform_instrument_pass2(tree temp)
{
    DEBUGLOG("========== Entered mx_xform_instrument_pass2 =============\n");

    // TODO figure out what to do with COMPONENT_REFs. ideally this should never come here.
    if (TREE_CODE(temp) == COMPONENT_REF)
        return NULL_TREE;

	tree instr_node = find_instr_node(temp);

    // Zahed: New mods
    if (instr_node == NULL_TREE)
        return NULL_TREE;

	tree struct_type = TREE_TYPE(instr_node);

	tree rz_orig_val = DECL_CHAIN(TYPE_FIELDS(struct_type));
	DEBUGLOG("============ Exiting mx_xform_instrument_pass2 =============\n");
	return mf_mark(build3 (COMPONENT_REF, TREE_TYPE(rz_orig_val),
				instr_node, rz_orig_val, NULL_TREE));
}


#if 0
/* The method walks the node hierarchy to the topmost node. This is
   exactly how its done in mudflap and has been borrowed.
*/
static tree
mf_walk_comp_ref(tree *tp, tree type, location_t location, \
        tree *addr_store, tree *base_store)
{
    tree var, t, addr, base, size;

    t = *tp;

    int component_ref_only = (TREE_CODE (t) == COMPONENT_REF);
    /* If we have a bitfield component reference, we must note the
       innermost addressable object in ELT, from which we will
       construct the byte-addressable bounds of the bitfield.  */
    tree elt = NULL_TREE;
    int bitfield_ref_p = (TREE_CODE (t) == COMPONENT_REF
            && DECL_BIT_FIELD_TYPE (TREE_OPERAND (t, 1)));

    /* Iterate to the top of the ARRAY_REF/COMPONENT_REF
       containment hierarchy to find the outermost VAR_DECL.  */
    var = TREE_OPERAND (t, 0);
    while (1)
    {
        if (bitfield_ref_p && elt == NULL_TREE
                && (TREE_CODE (var) == ARRAY_REF
                    || TREE_CODE (var) == COMPONENT_REF))
            elt = var;

        if (TREE_CODE (var) == ARRAY_REF)
        {
            component_ref_only = 0;
            var = TREE_OPERAND (var, 0);
        }
        else if (TREE_CODE (var) == COMPONENT_REF)
            var = TREE_OPERAND (var, 0);
        else if (INDIRECT_REF_P (var)
                || TREE_CODE (var) == MEM_REF)
        {
            base = TREE_OPERAND (var, 0);
            break;
        }
        else if (TREE_CODE (var) == VIEW_CONVERT_EXPR)
        {
            var = TREE_OPERAND (var, 0);
            if (CONSTANT_CLASS_P (var)
                    && TREE_CODE (var) != STRING_CST)
                return NULL_TREE;
        }
        else
        {
            DEBUGLOG("TREE_CODE(temp) : %s comp_ref_only = %d eligigle = %d\n", \
                    tree_code_name[(int)TREE_CODE(var)], component_ref_only, \
                    mf_decl_eligible_p(var));
            gcc_assert (TREE_CODE (var) == VAR_DECL
                    || TREE_CODE (var) == SSA_NAME /* TODO: Check this */
                    || TREE_CODE (var) == PARM_DECL
                    || TREE_CODE (var) == RESULT_DECL
                    || TREE_CODE (var) == STRING_CST);
            /* Don't instrument this access if the underlying
               variable is not "eligible".  This test matches
               those arrays that have only known-valid indexes,
               and thus are not labeled TREE_ADDRESSABLE.  */
            if (! mf_decl_eligible_p (var)) //TODO is this needed? || component_ref_only)
                return NULL_TREE;
            else
            {
                base = build1 (ADDR_EXPR,
                        build_pointer_type (TREE_TYPE (var)), var);
                break;
            }
        }
    }

    /* Handle the case of ordinary non-indirection structure
       accesses.  These have only nested COMPONENT_REF nodes (no
       INDIRECT_REF), but pass through the above filter loop.
       Note that it's possible for such a struct variable to match
       the eligible_p test because someone else might take its
       address sometime.  */

    /* We need special processing for bitfield components, because
       their addresses cannot be taken.  */
    if (bitfield_ref_p)
    {
        tree field = TREE_OPERAND (t, 1);

        if (TREE_CODE (DECL_SIZE_UNIT (field)) == INTEGER_CST)
            size = DECL_SIZE_UNIT (field);

        if (elt)
            elt = build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (elt)),
                    elt);
        addr = fold_convert_loc (location, ptr_type_node, elt ? elt : base);
        addr = fold_build2_loc (location, POINTER_PLUS_EXPR, ptr_type_node,
                addr, fold_convert_loc (location, sizetype,
                    byte_position (field)));
    }
    else
        addr = build1 (ADDR_EXPR, build_pointer_type (type), t);

    if (addr_store)
        *addr_store = addr;

    if (base_store)
        *base_store = addr;

    return var;
}
#endif

/* The method walks the node hierarchy to the topmost node. This is
   exactly how its done in mudflap and has been borrowed.
*/
static tree
mf_walk_n_instrument(tree *tp, bool *instrumented)
{
    tree t, temp;

    t = *tp;

    /* Iterate to the top of the ARRAY_REF/COMPONENT_REF
       containment hierarchy to find the outermost VAR_DECL.  */

    DEBUGLOG("Walking: TREE_CODE(t) : %s\n", tree_code_name[(int)TREE_CODE(t)]);
    if (TREE_CODE (t) == ARRAY_REF)
        TREE_OPERAND (t, 0) = mf_walk_n_instrument(&(TREE_OPERAND(t,0)), instrumented);
    else if (TREE_CODE (t) == COMPONENT_REF)
        TREE_OPERAND (t, 0) = mf_walk_n_instrument(&(TREE_OPERAND(t,0)), instrumented);
    else if (INDIRECT_REF_P (t)
            || TREE_CODE (t) == MEM_REF)
    {
        // TODO What to do here?
    }
    else if (TREE_CODE (t) == VIEW_CONVERT_EXPR)
    {
        // TODO handle this?
    }
    else
    {
        //gcc_assert (TREE_CODE (t) == VAR_DECL
        //            || TREE_CODE (t) == SSA_NAME /* TODO: Check this */
        //            || TREE_CODE (t) == PARM_DECL
        //            || TREE_CODE (t) == RESULT_DECL
        //            || TREE_CODE (t) == STRING_CST);
            /* Don't instrument this access if the underlying
               variable is not "eligible".  This test matches
               those arrays that have only known-valid indexes,
               and thus are not labeled TREE_ADDRESSABLE.  */
            if (! mf_decl_eligible_p (t)) //TODO is this needed? || component_ref_only)
                return t;
            else
            {
                if((temp = mx_xform_instrument_pass2(t)) == NULL_TREE)
                    DEBUGLOG("Uninstrumented ADDR_EXPR operand. Returning.\n");
                else{
                    t = temp;
                    *instrumented = 1;
                }
            }
        }
    return t;
}

static void
mf_xform_derefs_1 (gimple_stmt_iterator *iter, tree *tp,
		location_t location, tree dirflag)
{
	tree type, base=NULL_TREE, limit, addr, size, t, elt=NULL_TREE;
	tree temp, field, offset;
	bool check_red_flag = 0, instrumented = 0;
	tree fncall_param_val;
	gimple is_char_red_call;
	tree temp_instr, type_node;

    // TODO fix this to use our flag
	/* Don't instrument read operations.  */
	if (dirflag == integer_zero_node && flag_mudflap_ignore_reads)
		return;

	DEBUGLOG("TREE_CODE(t) = %s, mf_decl_eligible_p : %d\n", 
			tree_code_name[(int)TREE_CODE(*tp)], mf_decl_eligible_p(*tp));

	t = *tp;
	type = TREE_TYPE (t);

	if (type == error_mark_node)
		return;

	size = TYPE_SIZE_UNIT (type);

	/* Don't instrument marked nodes.  */
	if (mf_marked_p (t) && !mf_decl_eligible_p(t)){
		DEBUGLOG("Returning Here - 1\n");
		return;
	}

    if (TREE_CODE(t) == ADDR_EXPR || \
            TREE_CODE(t) == COMPONENT_REF || \
            TREE_CODE(t) == ARRAY_REF || \
            (TREE_CODE(t) == VAR_DECL && mf_decl_eligible_p(t)))
    {
        DEBUGLOG("------ INSTRUMENTING NODES ---------\n");
        temp = TREE_OPERAND(t, 0);

        if(temp && (TREE_CODE(temp) == STRING_CST || \
                TREE_CODE(temp) == FUNCTION_DECL)) // TODO Check this out? What do you do in this case?
            return;

        DEBUGLOG("TREE_CODE(temp) : %s\n", tree_code_name[(int)TREE_CODE(temp)]);

        if (TREE_CODE(t) == VAR_DECL)
            *tp = mf_walk_n_instrument(tp, &instrumented);
        else
            TREE_OPERAND(t,0) = mf_walk_n_instrument(&(TREE_OPERAND(t,0)), &instrumented);

        if (TREE_CODE(t) == ADDR_EXPR)
            return;
    } 

    DEBUGLOG("Pass2 derefs: entering deref section\n");

    type_node = NULL_TREE;
    //TODO move this to appropriate cases
    t = *tp;
	switch (TREE_CODE (t))
	{
		case ARRAY_REF:
		case COMPONENT_REF: // TODO check if following works for comp refs
			{ 
                DEBUGLOG("------ INSIDE CASE COMPONENT_REF  ---------\n");
                HOST_WIDE_INT bitsize, bitpos;
                tree inner, offset;
                int volatilep, unsignedp;
                enum machine_mode mode1;
                check_red_flag = 1; 
                inner = get_inner_reference (t, &bitsize, &bitpos, &offset,
                        &mode1, &unsignedp, &volatilep, false);
                if (!offset)
                    offset = size_zero_node;
                offset = size_binop (PLUS_EXPR, offset,
                        size_int (bitpos / BITS_PER_UNIT));
                addr = fold_build2_loc (location, POINTER_PLUS_EXPR, ptr_type_node,
                        build1 (ADDR_EXPR, build_pointer_type(type), inner), offset);
                break; // TODO continue?
            }

		case INDIRECT_REF:
			DEBUGLOG("------ INSIDE CASE INDIRECT_REF  ---------\n");
			check_red_flag = 1;
			addr = TREE_OPERAND (t, 0);
            break; // TODO continue?

		case MEM_REF:
			DEBUGLOG("------ INSIDE CASE MEM_REF  ---------\n");
			check_red_flag = 1;
			addr = fold_build2_loc (location, POINTER_PLUS_EXPR, TREE_TYPE (TREE_OPERAND (t, 0)),
					TREE_OPERAND (t, 0), fold_convert (sizetype, TREE_OPERAND (t, 1)));
            break;

		case TARGET_MEM_REF:
			DEBUGLOG("------ INSIDE CASE TARGET_MEM_REF  ---------\n");
			check_red_flag = 1;
			addr = tree_mem_ref_addr (ptr_type_node, t);
			break; // TODO do you want to do this case? find out what it does.

		case ARRAY_RANGE_REF:
			DEBUGLOG("------ INSIDE CASE ARRAY_RANGE_REF  ---------\n");
			DEBUGLOG("------ TODO not handled yet---------\n");
			return;

		case BIT_FIELD_REF:
			DEBUGLOG("------ INSIDE CASE BIT_FIELD_REF  ---------\n");
			DEBUGLOG("------ TODO not handled yet---------\n");
			return;

		default:
			DEBUGLOG("------ INSIDE CASE DEFAULT  ---------\n");
			if(mf_decl_eligible_p(t))
			{
                DEBUGLOG("Do you want to be here?\n");
                return;
				/*if((*tp = mx_xform_instrument_pass2(t)) == NULL_TREE){
					DEBUGLOG("Failed to set tree operand\n");
					return;
				}*/
			}
	}


    // Add the call to is_char_red
    if (check_red_flag) {
        DEBUGLOG("Entering is_char_red\n");
        fncall_param_val = fold_build2_loc (location, MEM_REF, ptr_type_node, addr, \
                            build_int_cst(build_pointer_type(type), 0));
        fncall_param_val = fold_convert_loc (location, unsigned_type_node, fncall_param_val);
        is_char_red_call = gimple_build_call (lbc_is_char_red_fndecl, 3, fncall_param_val, size, \
                            fold_convert_loc(location, ptr_type_node, addr));
        gimple_set_location (is_char_red_call, location);
        //debug_gimple_stmt(is_char_red_call);
        gsi_insert_before (iter, is_char_red_call, GSI_SAME_STMT);
        DEBUGLOG("Done with is_char_red\n");
    }
    DEBUGLOG("Exiting derefs \n");
}

/* Transform
   1) Memory references.
   2) BUILTIN_ALLOCA calls.
*/
static void
mf_xform_statements (void)
{
	basic_block bb, next;
	gimple_stmt_iterator i;
	int saved_last_basic_block = last_basic_block;
	enum gimple_rhs_class grhs_class;
    unsigned argc, j;

	bb = ENTRY_BLOCK_PTR ->next_bb;
	do
	{
		next = bb->next_bb;
		for (i = gsi_start_bb (bb); !gsi_end_p (i); gsi_next (&i))
		{
			gimple s = gsi_stmt (i);

			/* Only a few GIMPLE statements can reference memory.  */
			switch (gimple_code (s))
			{
				case GIMPLE_ASSIGN:
					DEBUGLOG("\n\n******** Gimlpe Assign LHS ***********\n");
					mf_xform_derefs_1 (&i, gimple_assign_lhs_ptr (s),
							gimple_location (s), integer_one_node);
					DEBUGLOG("******** Gimlpe Assign RHS ***********\n");
					mf_xform_derefs_1 (&i, gimple_assign_rhs1_ptr (s),
							gimple_location (s), integer_zero_node);
					grhs_class = get_gimple_rhs_class (gimple_assign_rhs_code (s));
					if (grhs_class == GIMPLE_BINARY_RHS)
						mf_xform_derefs_1 (&i, gimple_assign_rhs2_ptr (s),
								gimple_location (s), integer_zero_node);
					break;

				case GIMPLE_RETURN:
					if (gimple_return_retval (s) != NULL_TREE)
					{
						mf_xform_derefs_1 (&i, gimple_return_retval_ptr (s),
								gimple_location (s),
								integer_zero_node);
					}
					break;

				case GIMPLE_CALL:
					{
						tree fndecl = gimple_call_fndecl (s);
						//if (fndecl && (DECL_FUNCTION_CODE (fndecl) == BUILT_IN_ALLOCA))
						//	gimple_call_set_cannot_inline (s, true);

                        argc = gimple_call_num_args(s);
                        for (j = 0; j < argc; j++){
                            mf_xform_derefs_1 (&i, gimple_call_arg_ptr (s, j),
								gimple_location (s), integer_zero_node);
                        }
					}
					break;

				default:
					;
			}
		}
		bb = next;
	}
	while (bb && bb->index <= saved_last_basic_block);
}

/* ------------------------------------------------------------------------ */
/* ADDR_EXPR transforms.  Perform the declaration-related mudflap tree
   transforms on the current function.

   This is the first part of the mudflap instrumentation.  It works on
   high-level GIMPLE because after lowering, all variables are moved out
   of their BIND_EXPR binding context, and we lose liveness information
   for the declarations we wish to instrument.  */

static unsigned int
execute_mudflap_function_decls (void)
{
	struct gimplify_ctx gctx;
	DEBUGLOG("Zahed: entering LBC pass1\n");

	/* Don't instrument functions such as the synthetic constructor
	   built during mudflap_finish_file.  */
	if (mf_marked_p (current_function_decl) ||
			DECL_ARTIFICIAL (current_function_decl))
		return 0;

	push_gimplify_context (&gctx);

	mf_xform_decls (gimple_body (current_function_decl),
			DECL_ARGUMENTS (current_function_decl));

	pop_gimplify_context (NULL);
	return 0;
}

/* This struct is passed between mf_xform_decls to store state needed
   during the traversal searching for objects that have their
   addresses taken.  */
struct mf_xform_decls_data
{
  tree param_decls;
};

static tree
create_struct_type(tree decl, size_t front_rz_size, size_t rear_rz_size)
{
    // TODO make this dynamic rather than static
    char type_name[50];
    tree fieldfront, orig_var, fieldrear, struct_type;

    gcc_assert(front_rz_size % 8 == 0 && rear_rz_size % 8 == 0);

    struct_type = mf_mark(make_node (RECORD_TYPE));

    // Build the front red zone
    tree front_array_idx =  build_index_type (size_int (front_rz_size / sizeof(unsigned int)));
    tree front_rz_array = build_array_type (unsigned_type_node, front_array_idx);
    fieldfront = build_decl (UNKNOWN_LOCATION,
            FIELD_DECL, get_identifier ("rz_front"), front_rz_array);
    DECL_ALIGN(fieldfront) = 8;
    DECL_CONTEXT (fieldfront) = struct_type;

    // orig variable
    orig_var = build_decl (UNKNOWN_LOCATION,
            FIELD_DECL, get_identifier("orig_var"), TREE_TYPE(decl));
    DECL_CONTEXT (orig_var) = struct_type; // Look at comments above
    DECL_CHAIN (fieldfront) = orig_var;

    // Rear zone
    if (COMPLETE_TYPE_P(decl)){
        tree rear_array_idx =  build_index_type (size_int (rear_rz_size / sizeof(unsigned int)));
        tree rear_rz_array = build_array_type (unsigned_type_node, rear_array_idx);
        fieldrear = build_decl (UNKNOWN_LOCATION,
                FIELD_DECL, get_identifier ("rz_rear"), rear_rz_array);
        DECL_ALIGN(fieldrear) = 8;
        DECL_CONTEXT (fieldrear) = struct_type;
        DECL_CHAIN (orig_var) = fieldrear;
    }

    TYPE_FIELDS (struct_type) = fieldfront;

    strcpy(type_name, "rz_");
    strcat(type_name, get_name(decl));
    strcat(type_name, "_type");
    TYPE_NAME (struct_type) = get_identifier (type_name);
    layout_type (struct_type);

    return struct_type;
}

static tree
create_struct_var (tree type, tree decl, location_t location)
{
    char type_name[50];
    tree tmp_var;

    strcpy(type_name, "rz_");
    strcat(type_name, get_name(decl));

    tmp_var = build_decl (location,
            VAR_DECL, get_identifier(type_name),
            type);

    /* The variable was declared by the compiler.  */
    DECL_ARTIFICIAL (tmp_var) = 1;
    /* And we don't want debug info for it.  */
    DECL_IGNORED_P (tmp_var) = 1;

    /* Make the variable writable.  */
    TREE_READONLY (tmp_var) = 0;

    DECL_EXTERNAL (tmp_var) = 0;
    TREE_STATIC (tmp_var) = 0;
    TREE_USED (tmp_var) = 1;

    return tmp_var;
}

#define LBC_GLOBAL_FRONT_RZ_SIZE 128
#define LBC_MIN_ZONE_SIZE 8
#define LBC_MAX_ZONE_SIZE 1024

#ifndef MAX
#define MAX( a, b ) ( ((a) > (b)) ? (a) : (b) )
#endif

#ifndef MIN
#define MIN( a, b ) ( ((a) < (b)) ? (a) : (b) )
#endif

#define ROUNDUP( a, b ) (!((a) % (b)) ? (a) : (a) + ((b) - ((a) % (b))))

static void
calculate_zone_sizes(size_t element_size, size_t request_size, bool is_global, \
                    bool is_complete, size_t *fsize, size_t *rsize)
{
    size_t frontsz, rearsz;

    // Step A
    if (!is_global && is_complete){
        frontsz = MAX (2 * element_size, request_size / 8);
        rearsz = frontsz;
    }else if (is_global && is_complete){
        frontsz = LBC_GLOBAL_FRONT_RZ_SIZE;
        rearsz = MAX (0, (MAX (4 * element_size, request_size / 8) - frontsz));
    }else if(!is_complete){
        frontsz = LBC_GLOBAL_FRONT_RZ_SIZE;
        rearsz = 0;
    }


    // Step B
    frontsz = ROUNDUP(frontsz, 8);
    frontsz = frontsz > LBC_MAX_ZONE_SIZE ? LBC_MAX_ZONE_SIZE : frontsz;
    frontsz = frontsz < LBC_MIN_ZONE_SIZE ? LBC_MIN_ZONE_SIZE : frontsz;

    rearsz = ROUNDUP(rearsz, 8);
    rearsz = rearsz > LBC_MAX_ZONE_SIZE ? LBC_MAX_ZONE_SIZE : rearsz;
    rearsz = rearsz < LBC_MIN_ZONE_SIZE ? LBC_MIN_ZONE_SIZE : rearsz;

    // Return the result
    *fsize = frontsz;
    *rsize = rearsz;
}

/* Synthesize a CALL_EXPR and a TRY_FINALLY_EXPR, for this chain of
   _DECLs if appropriate.  Arrange to call the __mf_register function
   now, and the __mf_unregister function later for each.  Return the
   gimple sequence after synthesis.  */
gimple_seq
mx_register_decls (tree decl, gimple_seq seq, gimple stmt, location_t location, bool func_args)
{
    gimple_seq finally_stmts = NULL;
    gimple_stmt_iterator initially_stmts = gsi_start (seq);
    bool sframe_inserted = false;
    size_t front_rz_size, rear_rz_size;
    tree fsize, rsize, size;
    gimple uninit_fncall_front, uninit_fncall_rear, init_fncall_front, \
        init_fncall_rear, init_assign_stmt;
    tree fncall_param_front, fncall_param_rear;
    int map_ret;

    while (decl != NULL_TREE)
    {
        if ((mf_decl_eligible_p (decl) || TREE_CODE(TREE_TYPE(decl)) == ARRAY_TYPE)
                /* Not already processed.  */
                && ! mf_marked_p (decl)
                /* Automatic variable.  */
                && ! DECL_EXTERNAL (decl)
                && ! TREE_STATIC (decl)
                && get_name(decl))
        {
            DEBUGLOG("DEBUG Instrumenting %s is_complete_type %d\n", IDENTIFIER_POINTER(DECL_NAME(decl)), COMPLETE_TYPE_P(decl));

            /* construct a tree corresponding to the type struct{
               unsigned int rz_front[6U];
               original variable
               unsigned int rz_rear[6U];
               };
             */

            if (!sframe_inserted){
                gimple ensure_fn_call = gimple_build_call (lbc_ensure_sframe_bitmap_fndecl, 0);
                gimple_set_location (ensure_fn_call, location);
                gsi_insert_before (&initially_stmts, ensure_fn_call, GSI_SAME_STMT);

                sframe_inserted = true;
            }

            // Calculate the zone sizes
            size_t element_size = 0, request_size = 0;
            if (COMPLETE_TYPE_P(decl)){
                request_size = TREE_INT_CST_LOW(TYPE_SIZE_UNIT(TREE_TYPE(decl)));
                if (TREE_CODE(TREE_TYPE(decl)) == ARRAY_TYPE)
                    element_size = TREE_INT_CST_LOW(TYPE_SIZE_UNIT(TREE_TYPE(TREE_TYPE(decl))));
                else
                    element_size = request_size;
            }
            calculate_zone_sizes(element_size, request_size, /*global*/ false, COMPLETE_TYPE_P(decl), &front_rz_size, &rear_rz_size);
            DEBUGLOG("DEBUG *SIZES* req_size %u, ele_size %u, fsize %u, rsize %u\n", request_size, element_size, front_rz_size, rear_rz_size);
			
            tree struct_type = create_struct_type(decl, front_rz_size, rear_rz_size);
            tree struct_var = create_struct_var(struct_type, decl, location);
            declare_vars(struct_var, stmt, 0);

			/* Inserting into hashtable */
            PWord_t PV;
            JSLI(PV, decl_map, mf_varname_tree(decl));
            gcc_assert(PV);
            *PV = (PWord_t) struct_var;

            fsize = convert (unsigned_type_node, size_int(front_rz_size));
            gcc_assert (is_gimple_val (fsize));

            tree rz_front = TYPE_FIELDS(struct_type);
            fncall_param_front = mf_mark (build1 (ADDR_EXPR, ptr_type_node, build3 (COMPONENT_REF, TREE_TYPE(rz_front),
                                                      struct_var, rz_front, NULL_TREE)));
            uninit_fncall_front = gimple_build_call (lbc_uninit_front_rz_fndecl, 2, fncall_param_front, fsize);
            init_fncall_front = gimple_build_call (lbc_init_front_rz_fndecl, 2, fncall_param_front, fsize);
            gimple_set_location (init_fncall_front, location);
            gimple_set_location (uninit_fncall_front, location);

            // In complete types have only a front red zone
            if (COMPLETE_TYPE_P(decl)){
                rsize = convert (unsigned_type_node, size_int(rear_rz_size));
                gcc_assert (is_gimple_val (rsize));

                tree rz_rear = DECL_CHAIN(DECL_CHAIN(TYPE_FIELDS (struct_type)));
                fncall_param_rear = mf_mark (build1 (ADDR_EXPR, ptr_type_node, build3 (COMPONENT_REF, TREE_TYPE(rz_rear),
                                struct_var, rz_rear, NULL_TREE)));
                init_fncall_rear = gimple_build_call (lbc_init_rear_rz_fndecl, 2, fncall_param_rear, rsize);
                uninit_fncall_rear = gimple_build_call (lbc_uninit_rear_rz_fndecl, 2, fncall_param_rear, rsize);
                gimple_set_location (init_fncall_rear, location);
                gimple_set_location (uninit_fncall_rear, location);
            }

            // TODO Do I need this?
#if 0
            if (DECL_INITIAL(decl) != NULL_TREE){
                // This code never seems to be getting executed for somehting like int i = 10;
                // I have no idea why? But looking at the tree dump, seems like its because
                // by the time it gets here, these kind of statements are split into two statements
                // as int i; and i = 10; respectively. I am leaving it in just in case.
                tree orig_var_type = DECL_CHAIN(TYPE_FIELDS (struct_type));
                tree orig_var_lval = mf_mark (build3 (COMPONENT_REF, TREE_TYPE(orig_var_type),
                                        struct_var, orig_var_type, NULL_TREE));
                init_assign_stmt = gimple_build_assign(orig_var_lval, DECL_INITIAL(decl));
                gimple_set_location (init_assign_stmt, location);
            }
#endif

            if (gsi_end_p (initially_stmts))
            {
                // TODO handle this
                if (!DECL_ARTIFICIAL (decl))
                    warning (OPT_Wmudflap,
                            "mudflap cannot track %qE in stub function",
                            DECL_NAME (decl));
            }
            else
            {
#if 0
                // Insert the declaration initializer
                if (DECL_INITIAL(decl) != NULL_TREE)
                    gsi_insert_before (&initially_stmts, init_assign_stmt, GSI_SAME_STMT);
#endif

                //gsi_insert_before (&initially_stmts, register_fncall, GSI_SAME_STMT);
                gsi_insert_before (&initially_stmts, init_fncall_front, GSI_SAME_STMT);
                if (COMPLETE_TYPE_P(decl))
                    gsi_insert_before (&initially_stmts, init_fncall_rear, GSI_SAME_STMT);

                /* Accumulate the FINALLY piece.  */
                //gimple_seq_add_stmt (&finally_stmts, unregister_fncall);
                gimple_seq_add_stmt (&finally_stmts, uninit_fncall_front);
                if (COMPLETE_TYPE_P(decl))
                    gimple_seq_add_stmt (&finally_stmts, uninit_fncall_rear);

            }
            mf_mark (decl);
        }

        decl = DECL_CHAIN (decl);
    }

    /* Actually, (initially_stmts!=NULL) <=> (finally_stmts!=NULL) */
    if (finally_stmts != NULL)
    {
        gimple stmt = gimple_build_try (seq, finally_stmts, GIMPLE_TRY_FINALLY);
        gimple_seq new_seq = gimple_seq_alloc ();

        gimple_seq_add_stmt (&new_seq, stmt);
        return new_seq;
    }
    else
        return seq;
}


/* Process every variable mentioned in BIND_EXPRs.  */
static tree
mx_xfn_xform_decls (gimple_stmt_iterator *gsi,
        bool *handled_operands_p ATTRIBUTE_UNUSED,
        struct walk_stmt_info *wi)
{
    struct mf_xform_decls_data *d = (struct mf_xform_decls_data *) wi->info;
    gimple stmt = gsi_stmt (*gsi);

    switch (gimple_code (stmt))
    {
        case GIMPLE_BIND:
            {
                /* Process function parameters now (but only once).  */
                if (d->param_decls)
                {
                    gimple_bind_set_body (stmt,
                            mx_register_decls (d->param_decls,
                                gimple_bind_body (stmt), stmt,
                                gimple_location (stmt), 1));
                    d->param_decls = NULL_TREE;
                }

                gimple_bind_set_body (stmt,
                        mx_register_decls (gimple_bind_vars (stmt),
                            gimple_bind_body (stmt), stmt,
                            gimple_location (stmt), 0));
            }
            break;

        default:
            break;
    }

    return NULL_TREE;
}

/* Perform the object lifetime tracking mudflap transform on the given function
   tree.  The tree is mutated in place, with possibly copied subtree nodes.

   For every auto variable declared, if its address is ever taken
   within the function, then supply its lifetime to the mudflap
   runtime with the __mf_register and __mf_unregister calls.
*/

static void
mf_xform_decls (gimple_seq fnbody, tree fnparams)
{
  struct mf_xform_decls_data d;
  struct walk_stmt_info wi;
  struct pointer_set_t *pset = pointer_set_create ();

  d.param_decls = fnparams;
  memset (&wi, 0, sizeof (wi));
  wi.info = (void*) &d;
  wi.pset = pset;
  walk_gimple_seq (fnbody, mx_xfn_xform_decls, NULL, &wi);
  pointer_set_destroy (pset);
}


/* ------------------------------------------------------------------------ */
/* Externally visible functions.  */


/* Mark and return the given tree node to prevent further mudflap
   transforms.  */
static GTY ((param_is (union tree_node))) htab_t marked_trees = NULL;

tree
mf_mark (tree t)
{
  void **slot;

  if (marked_trees == NULL)
    marked_trees = htab_create_ggc (31, htab_hash_pointer, htab_eq_pointer,
				    NULL);

  slot = htab_find_slot (marked_trees, t, INSERT);
  *slot = t;
  return t;
}

int
mf_marked_p (tree t)
{
  void *entry;

  if (marked_trees == NULL)
    return 0;

  entry = htab_find (marked_trees, t);
  return (entry != NULL);
}
