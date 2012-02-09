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

int plugin_is_GPL_compatible;

/* Internal function decls */


/* Options.  */
#define flag_mudflap_threads (flag_mudflap == 2)

/* Helpers.  */
static tree mf_build_string (const char *string);
char* mf_varname_tree (tree);

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
static tree create_struct_type(tree decl);
static tree mx_xform_instrument_pass2(tree temp);

/* Helper method to build a string cst.
   Used by mf_build_asm
 */
static tree
mf_build_string1 (const char *string)
{
  size_t len = strlen (string);
  tree result = mf_mark (build_string (len + 1, string));

  TREE_TYPE (result) = build_array_type
    (char_type_node, build_index_type (build_int_cst (NULL_TREE, len)));
  TREE_CONSTANT (result) = 1;
  TREE_READONLY (result) = 1;
  TREE_STATIC (result) = 1;

  //result = build1 (ADDR_EXPR, build_pointer_type (char_type_node), result);

  return mf_mark (result);
}

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

//static tree
char * mf_varname_tree (tree decl)
{
	static pretty_printer buf_rec;
	static int initialized = 0;
	pretty_printer *buf = & buf_rec;
	const char *buf_contents;
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
	//printf("buf_contents : %s\n", buf_contents);
	result = mf_build_string (buf_contents);
	pp_clear_output_area (buf);

	//  return result;
	return buf_contents;
}



/* global tree nodes */

/* Global tree objects for global variables and functions exported by
   mudflap runtime library.  mf_init_extern_trees must be called
   before using these.  */

/* uintptr_t (usually "unsigned long") */
static GTY (()) tree mf_uintptr_type;

/* struct __mf_cache { uintptr_t low; uintptr_t high; }; */
static GTY (()) tree mf_cache_struct_type;

/* struct __mf_cache * const */
static GTY (()) tree mf_cache_structptr_type;

/* extern struct __mf_cache __mf_lookup_cache []; */
static GTY (()) tree mf_cache_array_decl;

/* extern unsigned char __mf_lc_shift; */
static GTY (()) tree mf_cache_shift_decl;

/* extern uintptr_t __mf_lc_mask; */
static GTY (()) tree mf_cache_mask_decl;

/* Their function-scope local shadows, used in single-threaded mode only.  */

/* auto const unsigned char __mf_lc_shift_l; */
static GTY (()) tree mf_cache_shift_decl_l;

/* auto const uintptr_t __mf_lc_mask_l; */
static GTY (()) tree mf_cache_mask_decl_l;

/* extern void __mf_check (void *ptr, size_t sz, int type, const char *); */
static GTY (()) tree mf_check_fndecl;

/* extern void __mf_register (void *ptr, size_t sz, int type, const char *); */
static GTY (()) tree mf_register_fndecl;

/* extern void __mf_unregister (void *ptr, size_t sz, int type); */
static GTY (()) tree mf_unregister_fndecl;

/* extern void __mf_init (); */
static GTY (()) tree mf_init_fndecl;

/* extern int __mf_set_options (const char*); */
static GTY (()) tree mf_set_options_fndecl;

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

#define HTABLE_MAX_ENTRY 1000
struct htable_entry myHtable[HTABLE_MAX_ENTRY];
int count = 0;


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

/* Helper for mudflap_init: construct a tree corresponding to the type
     struct __mf_cache { uintptr_t low; uintptr_t high; };
     where uintptr_t is the FIELD_TYPE argument.  */
static inline tree
mf_make_mf_cache_struct_type (tree field_type)
{
  /* There is, abominably, no language-independent way to construct a
     RECORD_TYPE.  So we have to call the basic type construction
     primitives by hand.  */
  tree fieldlo = build_decl (UNKNOWN_LOCATION,
			     FIELD_DECL, get_identifier ("low"), field_type);
  tree fieldhi = build_decl (UNKNOWN_LOCATION,
			     FIELD_DECL, get_identifier ("high"), field_type);

  tree struct_type = make_node (RECORD_TYPE);
  DECL_CONTEXT (fieldlo) = struct_type;
  DECL_CONTEXT (fieldhi) = struct_type;
  DECL_CHAIN (fieldlo) = fieldhi;
  TYPE_FIELDS (struct_type) = fieldlo;
  TYPE_NAME (struct_type) = get_identifier ("__mf_cache");
  layout_type (struct_type);

  return struct_type;
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

    printf("LBC Plugin: Building decls\n");

	lbc_const_void_ptr_type = build_qualified_type (ptr_type_node, TYPE_QUAL_CONST);

	lbc_init_uninit_rz_fntype =
		build_function_type_list (void_type_node, ptr_type_node,
				unsigned_type_node, NULL_TREE);
	lbc_ensure_sframe_fntype =
		build_function_type_list (void_type_node, void_type_node,
				NULL_TREE);

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
    printf("LBC Plugin: Done Building decls\n");
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
    struct register_pass_info pass_info0;
    struct register_pass_info pass_info1;
    struct register_pass_info pass_info2;
    const char *plugin_name = "LBC";

    struct plugin_info info = {"1.0", "Use -fplugin=path/to/lbc.so to use the lbc plugin"};

    printf("LBC Plugin: Initializing plugin version %s \n", info.version);

    // Check for build time versus run time gcc version
    if (!plugin_default_version_check (version, &gcc_version))
        return 1;

    // Start plugin related work here.
    register_callback (plugin_name, PLUGIN_START_UNIT, execute_lbc_init, NULL);

    // TODO for some reason the following call is giving a segfault in GCC code
    //register_callback (plugin_name, PLUGIN_INFO, NULL, &info);

    printf("LBC Plugin: Building pass1\n");
    pass_info1.pass = &pass_lbc_1.pass;
    pass_info1.reference_pass_name = "omplower";
    pass_info1.ref_pass_instance_number = 1;
    pass_info1.pos_op = PASS_POS_INSERT_BEFORE;

    printf("LBC Plugin: Registering pass1\n");
    register_callback (plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info1);

    printf("LBC Plugin: Building pass2\n");
    pass_info2.pass = &pass_lbc_2.pass;
    pass_info2.reference_pass_name = "ssa";
    pass_info2.ref_pass_instance_number = 1;
    pass_info2.pos_op = PASS_POS_INSERT_AFTER;

    printf("LBC Plugin: Registering pass2\n");
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
	printf("Zahed: entering LBC pass2\n");
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
	int i = 0;
	while(i < count){
		//printf("myHtable[i].name : %s, mf_varname_tree(temp) : %s\n", 
		//	myHtable[i].name, mf_varname_tree(temp));
		if(strcmp(myHtable[i].name, mf_varname_tree(temp)) == 0){
			//printf("---------------- match found --------------------\n\n");
			return myHtable[i].t_name;
		}
		i++;
	}
	//printf("---------------- NO match found --------------------\n\n");
	return NULL_TREE;
}

static tree mx_xform_instrument_pass2(tree temp)
{
	//	printf("========== Entered mx_xform_instrument_pass2, count : %d =============\n", count);
	tree instr_node = find_instr_node(temp);
	tree struct_type = TREE_TYPE(instr_node);

	tree rz_orig_val = DECL_CHAIN(TYPE_FIELDS(struct_type));
	//printf("============ Exiting mx_xform_instrument_pass2 =============\n");
	return mf_mark(build3 (COMPONENT_REF, TREE_TYPE(rz_orig_val),
				instr_node, rz_orig_val, NULL_TREE));
}

#if 0
static tree
mx_xform_instrument_pass2(tree temp)
{
	char instr_tree_name[50] = {0,};
	tree struct_type = create_struct_type(temp);
	tree rz_orig_val = DECL_CHAIN(TYPE_FIELDS(struct_type));
	strcpy(instr_tree_name, "rz_");
	strcat(instr_tree_name, get_name(temp));
	return mf_mark(build3 (COMPONENT_REF, TREE_TYPE(rz_orig_val),
			get_identifier(instr_tree_name), rz_orig_val, NULL_TREE));
}
#endif

static tree decode_array_ref(tree t, tree temp_instr)
{
					tree t2 = t;
					tree off_tree = size_zero_node;
					tree index = TREE_OPERAND (t2, 1);
					tree low_bound = array_ref_low_bound (t2);
					tree unit_size = array_ref_element_size (t2);
						
					if (! integer_zerop (low_bound))
						index = fold_build2 (MINUS_EXPR, TREE_TYPE (index), index, low_bound);
						
					off_tree = size_binop (PLUS_EXPR,
								size_binop (MULT_EXPR, fold_convert (sizetype, index), unit_size),
								off_tree);

					tree fournode = size_binop (PLUS_EXPR,
						fold_convert(sizetype,integer_one_node), 
						fold_convert(sizetype,integer_three_node));
					tree sixnode = size_binop (PLUS_EXPR,
						fold_convert(sizetype,integer_three_node), 
						fold_convert(sizetype,integer_three_node));
					tree front_rz_offset= size_binop (MULT_EXPR,
						fold_convert(sizetype, fournode), 
						fold_convert(sizetype, sixnode));
					front_rz_offset = size_binop (MINUS_EXPR,
						fold_convert(sizetype, front_rz_offset), 
						fold_convert(sizetype,integer_one_node));
					tree final_offset = size_binop (PLUS_EXPR, 
						fold_convert(sizetype, front_rz_offset), 
						fold_convert(sizetype, off_tree));
					tree origvar = build1 (ADDR_EXPR, 
						build_pointer_type (TREE_TYPE(TREE_OPERAND (temp_instr, 0))), 
						TREE_OPERAND (temp_instr, 0));

					tree addr = fold_convert(ptr_type_node, origvar);
					addr = fold_build2(POINTER_PLUS_EXPR, ptr_type_node,
							addr, fold_convert(sizetype, final_offset));
					return addr;
}

static void
mf_xform_derefs_1 (gimple_stmt_iterator *iter, tree *tp,
		location_t location, tree dirflag)
{
	tree type, base=NULL_TREE, limit, addr, size, t, elt=NULL_TREE;
	tree temp, field, offset;
	bool check_red_flag = 0;
	tree fncall_param_val;
	gimple is_char_red_call;
	tree temp_instr, type_node;

	/* Don't instrument read operations.  */
	if (dirflag == integer_zero_node && flag_mudflap_ignore_reads)
		return;

	printf("TREE_CODE(t) = %s, mf_decl_eligible_p : %d\n", 
			tree_code_name[(int)TREE_CODE(*tp)], mf_decl_eligible_p(*tp));

	t = *tp;
	type = TREE_TYPE (t);

	if (type == error_mark_node)
		return;

	size = TYPE_SIZE_UNIT (type);

	/* Don't instrument marked nodes.  */
	if (mf_marked_p (t) && !mf_decl_eligible_p(t)){
		printf("Returning Here - 1\n");
		return;
	}

    type_node = NULL_TREE;
	switch (TREE_CODE (t))
	{
		case ADDR_EXPR:
			{
				printf("------ INSIDE CASE ADDR_EXPR ---------\n");
				temp = TREE_OPERAND(t, 0);
				if(TREE_CODE(temp) == STRING_CST)
					return;
				printf("TREE_CODE(temp) : %s\n", tree_code_name[(int)TREE_CODE(temp)]);
				if((TREE_OPERAND (t, 0) = mx_xform_instrument_pass2(temp)) == NULL_TREE)
					printf("Failed to set tree operand\n");
				return;
			}
		case ARRAY_REF:
		case COMPONENT_REF:
			{
				check_red_flag = 1;
				temp = TREE_OPERAND(t, 0);
				if(TREE_CODE(t) == ARRAY_REF) {
					printf("------ INSIDE CASE ARRAY_REF  ---------\n");
					//printf("TREE_CODE(temp) : %s\n", tree_code_name[(int)TREE_CODE(temp)]);
					tree temp_instr = mx_xform_instrument_pass2(temp);
					if(temp_instr == NULL_TREE){
						printf("Failed to get tree operand\n");
						return;
					}
                    type_node = TREE_TYPE(TREE_TYPE(temp));
					addr = decode_array_ref(t, temp_instr);
					base = addr;
					TREE_OPERAND(t, 0) = temp_instr;
					break;
				}
				else if(TREE_CODE(t) == COMPONENT_REF) {
					printf("------ INSIDE CASE COMPONENT_REF  ---------\n");
					temp = TREE_OPERAND(t, 0);
					if(mf_decl_eligible_p(temp))
					{
						printf("Elig decl\n");
						TREE_OPERAND(t, 0) = mx_xform_instrument_pass2(temp);
						if(TREE_OPERAND(t, 0) == NULL_TREE){
							printf("Failed to get tree operand\n");
							return;
						}
						return;
					}
					else if(TREE_CODE(TREE_OPERAND(t,0)) == MEM_REF){
						printf("Sub - memref\n");
						tree field = TREE_OPERAND (t, 1);
						tree offset = component_ref_field_offset (t);
						if (! DECL_SIZE_UNIT (field)){
							printf("expr NULL_TREE\n");
							return;
						}
						addr = build1 (ADDR_EXPR, build_pointer_type(TREE_TYPE(field)), field);
						//addr = TREE_OPERAND (var, 0);
						//base = build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (var)), var);
						//base = build1 (ADDR_EXPR, build_pointer_type (type), t);
						base = fold_build2(POINTER_PLUS_EXPR, ptr_type_node,
										t, fold_convert(sizetype, offset));						
					}
					else
						return;
					//TREE_OPERAND(t, 0) = temp_instr;
					//addr = build1 (ADDR_EXPR, build_pointer_type (type), t);
					//base = addr;
					break;
				}
				#if 0
				tree var;
				int component_ref_only = (TREE_CODE (t) == COMPONENT_REF);
				int while_count = 0;
				var = TREE_OPERAND (t, 0);
				while (1){
					printf("Inside while\n");
					/* Iterate to the top of the ARRAY_REF/COMPONENT_REF
					   containment hierarchy to find the outermost VAR_DECL.  */
					if (TREE_CODE (var) == ARRAY_REF){
						printf("1\n");
						component_ref_only = 0;
						var = TREE_OPERAND (var, 0);
					}
					else if (TREE_CODE (var) == COMPONENT_REF){
						var = TREE_OPERAND (var, 0);
						printf("2\n");
					}
					else if (INDIRECT_REF_P (var) || TREE_CODE (var) == MEM_REF){
						tree field = TREE_OPERAND (t, 1);
						tree offset = component_ref_field_offset (t);
						if (! DECL_SIZE_UNIT (field)){
							printf("expr NULL_TREE\n");
							break;
						}
						addr = build1 (ADDR_EXPR, build_pointer_type(TREE_TYPE(var)), var);
						//addr = TREE_OPERAND (var, 0);
						//base = build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (var)), var);
						//base = build1 (ADDR_EXPR, build_pointer_type (type), t);
						base = fold_build2(POINTER_PLUS_EXPR, ptr_type_node,
									addr, fold_convert(sizetype, offset));
						break;
					}
					else if (TREE_CODE (var) == VIEW_CONVERT_EXPR){
						printf("4\n");
						var = TREE_OPERAND (var, 0);
						if (CONSTANT_CLASS_P (var) && TREE_CODE (var) != STRING_CST){
							printf("Returning at 1\n");
							return;
						}
					}
					else{
						printf("5 - TREE_CODE(var) : %s\n", tree_code_name[(int)TREE_CODE(var)]);
						gcc_assert (TREE_CODE (var) == VAR_DECL || TREE_CODE (var) == PARM_DECL
								|| TREE_CODE (var) == RESULT_DECL || TREE_CODE (var) == STRING_CST);
						/*Don't instrument this access if the underlying variable is not "eligible".  This test matches
						   those arrays that have only known-valid indexes, and thus are not labeled TREE_ADDRESSABLE.*/
						if ((! mf_decl_eligible_p (var) || component_ref_only)){
							//if((TREE_CODE(t) == ARRAY_REF) && (while_count < 2)){
								printf("while_count : %d\n", while_count);
								printf("Returning at 2\n");
								return;
							//}
							//else if((TREE_CODE(t) == ARRAY_REF) && while_count == 2){
							//	base = build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (var)), var);
							//	break;
							//}
						}
						else{
							base = build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (var)), var);
							break;
						}
					}
				}
				#endif
				//if(base == NULL_TREE){
					//addr = build1 (ADDR_EXPR, build_pointer_type (type), t);
					//base = addr;
				//}
				#if 0
				limit = fold_build2_loc (location, MINUS_EXPR, mf_uintptr_type,
						fold_build2_loc (location, PLUS_EXPR, mf_uintptr_type,
						convert (mf_uintptr_type, addr),
						size), integer_one_node);
				#endif
				break;
			}

		case INDIRECT_REF:
			printf("------ INSIDE CASE INDIRECT_REF  ---------\n");
			check_red_flag = 1;
			addr = TREE_OPERAND (t, 0);
			base = addr;
			#if 0
			//limit = fold_build2_loc (location, POINTER_PLUS_EXPR, ptr_type_node,
					fold_build2_loc (location,
						POINTER_PLUS_EXPR, ptr_type_node, base,
						size),
					size_int (-1));
			#endif
			break;

		case MEM_REF:
			printf("------ INSIDE CASE MEM_REF  ---------\n");
			check_red_flag = 1;
            type_node = TREE_TYPE(TREE_OPERAND(t, 0));
			addr = fold_build2_loc (location, POINTER_PLUS_EXPR, TREE_TYPE (TREE_OPERAND (t, 0)),
					TREE_OPERAND (t, 0), fold_convert (sizetype, TREE_OPERAND (t, 1)));
			base = addr;
			#if 0
			limit = fold_build2_loc (location, POINTER_PLUS_EXPR, ptr_type_node,
					fold_build2_loc (location,
						POINTER_PLUS_EXPR, ptr_type_node, base,
						size),
						size_int (-1));
			#endif
			break;

		case TARGET_MEM_REF:
			printf("------ INSIDE CASE TARGET_MEM_REF  ---------\n");
			return;
			#if 0
			addr = tree_mem_ref_addr (ptr_type_node, t);
			base = addr;
			limit = fold_build2_loc (location, POINTER_PLUS_EXPR, ptr_type_node,
					fold_build2_loc (location,
						POINTER_PLUS_EXPR, ptr_type_node, base,
						size),
					size_int (-1));
			break;
			#endif

		case ARRAY_RANGE_REF:
			printf("------ INSIDE CASE ARRAY_RANGE_REF  ---------\n");
			return;
			#if 0
			warning (OPT_Wmudflap,
					"mudflap checking not yet implemented for ARRAY_RANGE_REF");
			return;
			#endif

		case BIT_FIELD_REF:
			printf("------ INSIDE CASE BIT_FIELD_REF  ---------\n");
			return;
			#if 0
			/* ??? merge with COMPONENT_REF code above? */
			{
				tree ofs, rem, bpu;

				/* If we're not dereferencing something, then the access
				   must be ok.  */
				if (TREE_CODE (TREE_OPERAND (t, 0)) != INDIRECT_REF)
					return;

				bpu = bitsize_int (BITS_PER_UNIT);
				ofs = convert (bitsizetype, TREE_OPERAND (t, 2));
				rem = size_binop_loc (location, TRUNC_MOD_EXPR, ofs, bpu);
				ofs = fold_convert_loc (location,
						sizetype,
						size_binop_loc (location,
							TRUNC_DIV_EXPR, ofs, bpu));

				size = convert (bitsizetype, TREE_OPERAND (t, 1));
				size = size_binop_loc (location, PLUS_EXPR, size, rem);
				size = size_binop_loc (location, CEIL_DIV_EXPR, size, bpu);
				size = convert (sizetype, size);

				addr = TREE_OPERAND (TREE_OPERAND (t, 0), 0);
				addr = convert (ptr_type_node, addr);
				addr = fold_build2_loc (location, POINTER_PLUS_EXPR,
						ptr_type_node, addr, ofs);

				base = addr;
				#if 0
				limit = fold_build2_loc (location, POINTER_PLUS_EXPR, ptr_type_node,
						fold_build2_loc (location,
							POINTER_PLUS_EXPR, ptr_type_node,
							base, size),
						size_int (-1));
				#endif
			}
			#endif
			break;

		default:
			printf("------ INSIDE CASE DEFAULT  ---------\n");
			if(mf_decl_eligible_p(t))
			{
				if((*tp = mx_xform_instrument_pass2(t)) == NULL_TREE){
					printf("Failed to set tree operand\n");
					return;
				}
			}
	}


    // Add the call to is_char_red
    if (check_red_flag) {
        printf("Entering is_char_red\n");
        //fncall_param_val = fold_build2_loc (location, MEM_REF, unsigned_type_node, base, \
        //                    build_int_cst(build_pointer_type(unsigned_type_node), 0));
        gcc_assert(type_node);
        fncall_param_val = fold_build2_loc (location, MEM_REF, type_node, base, \
                            build_int_cst(build_pointer_type(type_node), 0));
        fncall_param_val = fold_convert_loc (location, unsigned_type_node, fncall_param_val);
        is_char_red_call = gimple_build_call (lbc_is_char_red_fndecl, 3, fncall_param_val, size, \
                            fold_convert_loc(location, ptr_type_node, base));
        gimple_set_location (is_char_red_call, location);
        debug_gimple_stmt(is_char_red_call);
        gsi_insert_before (iter, is_char_red_call, GSI_SAME_STMT);
        printf("Done with is_char_red\n");
    }
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
					printf("\n\n******** Gimlpe Assign LHS ***********\n");
					mf_xform_derefs_1 (&i, gimple_assign_lhs_ptr (s),
							gimple_location (s), integer_one_node);
					printf("******** Gimlpe Assign RHS ***********\n");
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
						if (fndecl && (DECL_FUNCTION_CODE (fndecl) == BUILT_IN_ALLOCA))
							gimple_call_set_cannot_inline (s, true);
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
	printf("Zahed: entering LBC pass1\n");

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
create_struct_type(tree decl)
{
    char type_name[50];
    tree array_idx =  build_index_type (size_int (6U)); // TODO the size needs to be computed on the fly. How?
    tree rz_array = build_array_type (unsigned_type_node, array_idx);

    tree fieldfront = build_decl (UNKNOWN_LOCATION,
            FIELD_DECL, get_identifier ("rz_front"), rz_array);
    /* TODO we would need another one for orig_var? Question: how do we copy
     *      decl and remove it from original location?
     */
    tree orig_var = build_decl (UNKNOWN_LOCATION,
            FIELD_DECL, get_identifier("orig_var"), TREE_TYPE(decl));
    tree fieldrear = build_decl (UNKNOWN_LOCATION,
            FIELD_DECL, get_identifier ("rz_rear"), rz_array);

    tree struct_type = mf_mark(make_node (RECORD_TYPE));

    // TODO changes here. verify. orig_var needs to be inserted above.
    DECL_CONTEXT (fieldfront) = struct_type;
    DECL_CONTEXT (orig_var) = struct_type; // Look at comments above
    DECL_CONTEXT (fieldrear) = struct_type;
    DECL_CHAIN (fieldfront) = orig_var;
    DECL_CHAIN (orig_var) = fieldrear;
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

static gimple
mf_build_asm (char *asm_str, tree output, bool volatile_p)
{
    VEC(tree,gc) *inputs;
    VEC(tree,gc) *outputs;
    VEC(tree,gc) *clobbers;
    VEC(tree,gc) *labels;

    inputs = clobbers = labels = NULL;

    output = build_tree_list(build_tree_list(NULL, mf_build_string1("=g")), output);
    VEC_safe_push(tree, gc, outputs, output);
    gimple stmt = gimple_build_asm_vec (asm_str, \
            inputs, outputs, clobbers, labels);
    gimple_asm_set_volatile(stmt, volatile_p);
    gimple_asm_set_input (stmt, false);
    return stmt;
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

    while (decl != NULL_TREE)
    {
        if ((mf_decl_eligible_p (decl) || TREE_CODE(TREE_TYPE(decl)) == ARRAY_TYPE)
                /* Not already processed.  */
                && ! mf_marked_p (decl)
                /* Automatic variable.  */
                && ! DECL_EXTERNAL (decl)
                && ! TREE_STATIC (decl))
        {

            /* construct a tree corresponding to the type struct{
               unsigned int rz_front[6U];
               original variable
               unsigned int rz_rear[6U];
               };
             */

            if (!func_args && !sframe_inserted){
                tree frame_start, frame_end;
                gimple stmt_esp, stmt_ebp;
                char *asm_esp = "mov %%esp, %0";
                char *asm_ebp = "mov %%ebp, %0";

                frame_start = mf_mark (build_decl (location,
                                       VAR_DECL, get_identifier ("frame_start"), ptr_type_node));
                frame_end = mf_mark (build_decl (location,
                                       VAR_DECL, get_identifier ("frame_end"), ptr_type_node));
                DECL_CHAIN(frame_start) = frame_end;
                declare_vars(frame_start, stmt, 0);

                stmt_esp = mf_build_asm(asm_esp, frame_start, true);
                stmt_ebp = mf_build_asm(asm_ebp, frame_end, true);

                gsi_insert_before (&initially_stmts, stmt_esp, GSI_SAME_STMT);
                gsi_insert_before (&initially_stmts, stmt_ebp, GSI_SAME_STMT);

                gimple ensure_fn_call = gimple_build_call (lbc_ensure_sframe_bitmap_fndecl, \
                                            2, frame_start, frame_end);
                gimple_set_location (ensure_fn_call, location);
                gsi_insert_before (&initially_stmts, ensure_fn_call, GSI_SAME_STMT);

                sframe_inserted = true;
            }
			
            tree struct_type = create_struct_type(decl);
            tree struct_var = create_struct_var(struct_type, decl, location);
            declare_vars(struct_var, stmt, 0);

			/* Inserting into hashtable */
			strcpy(myHtable[count].name, mf_varname_tree(decl));
			myHtable[count].t_name = struct_var;
			count++;

			//printf("Pass1 IDPTR : %s\n",IDENTIFIER_POINTER(DECL_NAME(struct_var)));
            tree size = NULL_TREE;
            gimple uninit_fncall_front, uninit_fncall_rear, init_fncall_front, \
                            init_fncall_rear, init_assign_stmt;
            tree fncall_param_front, fncall_param_rear;
            /* Variable-sized objects should have sizes already been
               gimplified when we got here. */
            size = convert (unsigned_type_node, size_int(8U)); // TODO is this right? we need to provide size of RZ here.
            gcc_assert (is_gimple_val (size));

            // Need to change mf_mark
            // TODO first paramter is void * pointer to the rz field (front or rear). not struct type.
            //      Moreover, there are only two parameters, unlike mudflap's calls.
            // fncall_param_front = mf_mark (build1 (ADDR_EXPR, ptr_type_node, fieldfront));
            // fncall_param_rear = mf_mark (build1 (ADDR_EXPR, ptr_type_node, fieldrear));
            tree rz_front = TYPE_FIELDS(struct_type);
            tree rz_rear = DECL_CHAIN(DECL_CHAIN(TYPE_FIELDS (struct_type)));
            fncall_param_front = mf_mark (build1 (ADDR_EXPR, ptr_type_node, build3 (COMPONENT_REF, TREE_TYPE(rz_front),
                                                      struct_var, rz_front, NULL_TREE)));
            fncall_param_rear = mf_mark (build1 (ADDR_EXPR, ptr_type_node, build3 (COMPONENT_REF, TREE_TYPE(rz_rear),
                                                      struct_var, rz_rear, NULL_TREE)));

            uninit_fncall_front = gimple_build_call (lbc_uninit_front_rz_fndecl, 2, fncall_param_front, size);
            uninit_fncall_rear = gimple_build_call (lbc_uninit_rear_rz_fndecl, 2, fncall_param_rear, size);

            init_fncall_front = gimple_build_call (lbc_init_front_rz_fndecl, 2, fncall_param_front, size);
            init_fncall_rear = gimple_build_call (lbc_init_rear_rz_fndecl, 2, fncall_param_rear, size);

            gimple_set_location (init_fncall_front, location);
            gimple_set_location (init_fncall_rear, location);
            gimple_set_location (uninit_fncall_front, location);
            gimple_set_location (uninit_fncall_rear, location);

            // Handle the initializer in the declaration
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

            if (gsi_end_p (initially_stmts))
            {
                if (!DECL_ARTIFICIAL (decl))
                    warning (OPT_Wmudflap,
                            "mudflap cannot track %qE in stub function",
                            DECL_NAME (decl));
            }
            else
            {
                // Insert the declaration initializer
                if (DECL_INITIAL(decl) != NULL_TREE)
                    gsi_insert_before (&initially_stmts, init_assign_stmt, GSI_SAME_STMT);

                //gsi_insert_before (&initially_stmts, register_fncall, GSI_SAME_STMT);
                gsi_insert_before (&initially_stmts, init_fncall_front, GSI_SAME_STMT);
                gsi_insert_before (&initially_stmts, init_fncall_rear, GSI_SAME_STMT);

                /* Accumulate the FINALLY piece.  */
                //gimple_seq_add_stmt (&finally_stmts, unregister_fncall);
                gimple_seq_add_stmt (&finally_stmts, uninit_fncall_front);
                gimple_seq_add_stmt (&finally_stmts, uninit_fncall_rear);

                // TODO what about ensure_sframe_bitmap()?
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
/* Externally visible mudflap functions.  */


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

/* Remember given node as a static of some kind: global data,
   function-scope static, or an anonymous constant.  Its assembler
   label is given.  */

/* A list of globals whose incomplete declarations we encountered.
   Instead of emitting the __mf_register call for them here, it's
   delayed until program finish time.  If they're still incomplete by
   then, warnings are emitted.  */

static GTY (()) VEC(tree,gc) *deferred_static_decls;

/* A list of statements for calling __mf_register() at startup time.  */
static GTY (()) tree enqueued_call_stmt_chain;

static void
mudflap_register_call (tree obj, tree object_size, tree varname)
{
  tree arg, call_stmt;

  arg = build1 (ADDR_EXPR, build_pointer_type (TREE_TYPE (obj)), obj);
  arg = convert (ptr_type_node, arg);

  call_stmt = build_call_expr (mf_register_fndecl, 4,
			       arg,
			       convert (size_type_node, object_size),
			       /* __MF_TYPE_STATIC */
			       build_int_cst (NULL_TREE, 4),
			       varname);

  append_to_statement_list (call_stmt, &enqueued_call_stmt_chain);
}

void
mudflap_enqueue_decl (tree obj)
{
  if (mf_marked_p (obj))
    return;

  /* We don't need to process variable decls that are internally
     generated extern.  If we did, we'd end up with warnings for them
     during mudflap_finish_file ().  That would confuse the user,
     since the text would refer to variables that don't show up in the
     user's source code.  */
  if (DECL_P (obj) && DECL_EXTERNAL (obj) && DECL_ARTIFICIAL (obj))
    return;

  VEC_safe_push (tree, gc, deferred_static_decls, obj);
}


void
mudflap_enqueue_constant (tree obj)
{
  tree object_size, varname;

  if (mf_marked_p (obj))
    return;

  if (TREE_CODE (obj) == STRING_CST)
    object_size = build_int_cst (NULL_TREE, TREE_STRING_LENGTH (obj));
  else
    object_size = size_in_bytes (TREE_TYPE (obj));

  if (TREE_CODE (obj) == STRING_CST)
    varname = mf_build_string ("string literal");
  else
    varname = mf_build_string ("constant");

  mudflap_register_call (obj, object_size, varname);
}

