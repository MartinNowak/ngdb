/*-
 * Copyright (c) 2009-2010 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

module debuginfo.dwarf;

//debug = line;

import objfile.objfile;
import debuginfo.debuginfo;
import debuginfo.language;
import debuginfo.types;
import machine.machine;
static import std.path;
import std.algorithm;
import std.array;
import std.conv;
import std.string;
import std.stdio;
version(tangobos) import std.compat;
//import std.c.unix.unix;

import target.target;

enum {
    DW_TAG_array_type			= 0x01,
    DW_TAG_class_type			= 0x02,
    DW_TAG_entry_point			= 0x03,
    DW_TAG_enumeration_type		= 0x04,
    DW_TAG_formal_parameter		= 0x05,
    DW_TAG_imported_declaration		= 0x08,
    DW_TAG_label			= 0x0a,
    DW_TAG_lexical_block		= 0x0b,
    DW_TAG_member			= 0x0d,
    DW_TAG_pointer_type			= 0x0f,
    DW_TAG_reference_type		= 0x10,
    DW_TAG_compile_unit			= 0x11,
    DW_TAG_string_type			= 0x12,
    DW_TAG_structure_type		= 0x13,
    DW_TAG_subroutine_type		= 0x15,
    DW_TAG_typedef			= 0x16,
    DW_TAG_union_type			= 0x17,
    DW_TAG_unspecified_parameters	= 0x18,
    DW_TAG_variant			= 0x19,
    DW_TAG_common_block			= 0x1a,
    DW_TAG_common_inclusion		= 0x1b,
    DW_TAG_inheritance			= 0x1c,
    DW_TAG_inlined_subroutine		= 0x1d,
    DW_TAG_module			= 0x1e,
    DW_TAG_ptr_to_member_type		= 0x1f,
    DW_TAG_set_type			= 0x20,
    DW_TAG_subrange_type		= 0x21,
    DW_TAG_with_stmt			= 0x22,
    DW_TAG_access_declaration		= 0x23,
    DW_TAG_base_type			= 0x24,
    DW_TAG_catch_block			= 0x25,
    DW_TAG_const_type			= 0x26,
    DW_TAG_constant			= 0x27,
    DW_TAG_enumerator			= 0x28,
    DW_TAG_file_typei			= 0x29,
    DW_TAG_friend			= 0x2a,
    DW_TAG_namelist			= 0x2b,
    DW_TAG_namelist_item		= 0x2c,
    DW_TAG_packed_type			= 0x2d,
    DW_TAG_subprogram			= 0x2e,
    DW_TAG_template_type_parameter	= 0x2f,
    DW_TAG_template_value_parameter	= 0x30,
    DW_TAG_thrown_type			= 0x31,
    DW_TAG_try_block			= 0x32,
    DW_TAG_variant_part			= 0x33,
    DW_TAG_variable			= 0x34,
    DW_TAG_volatile_type		= 0x35,
    DW_TAG_dwarf_procedure		= 0x36,
    DW_TAG_restrict_type		= 0x37,
    DW_TAG_interface_type		= 0x38,
    DW_TAG_namespace			= 0x39,
    DW_TAG_imported_module		= 0x3a,
    DW_TAG_unspecified_type		= 0x3b,
    DW_TAG_partial_unit			= 0x3c,
    DW_TAG_imported_unit		= 0x3d,
    DW_TAG_condition			= 0x3f,
    DW_TAG_shared_type			= 0x40,

    // D programming language extensions
    DW_TAG_darray_type			= 0x41,
    DW_TAG_aarray_type			= 0x42,
    DW_TAG_delegate_type		= 0x43,

    DW_TAG_lo_user			= 0x4080,
    DW_TAG_hi_user			= 0xffff
}

string tagNames[] = [
    0x01: "DW_TAG_array_type",
    0x02: "DW_TAG_class_type",
    0x03: "DW_TAG_entry_point",
    0x04: "DW_TAG_enumeration_type",
    0x05: "DW_TAG_formal_parameter",
    0x08: "DW_TAG_imported_declaration",
    0x0a: "DW_TAG_label",
    0x0b: "DW_TAG_lexical_block",
    0x0d: "DW_TAG_member",
    0x0f: "DW_TAG_pointer_type",
    0x10: "DW_TAG_reference_type",
    0x11: "DW_TAG_compile_unit",
    0x12: "DW_TAG_string_type",
    0x13: "DW_TAG_structure_type",
    0x15: "DW_TAG_subroutine_type",
    0x16: "DW_TAG_typedef",
    0x17: "DW_TAG_union_type",
    0x18: "DW_TAG_unspecified_parameters",
    0x19: "DW_TAG_variant",
    0x1a: "DW_TAG_common_block",
    0x1b: "DW_TAG_common_inclusion",
    0x1c: "DW_TAG_inheritance",
    0x1d: "DW_TAG_inlined_subroutine",
    0x1e: "DW_TAG_module",
    0x1f: "DW_TAG_ptr_to_member_type",
    0x20: "DW_TAG_set_type",
    0x21: "DW_TAG_subrange_type",
    0x22: "DW_TAG_with_stmt",
    0x23: "DW_TAG_access_declaration",
    0x24: "DW_TAG_base_type",
    0x25: "DW_TAG_catch_block",
    0x26: "DW_TAG_const_type",
    0x27: "DW_TAG_constant",
    0x28: "DW_TAG_enumerator",
    0x29: "DW_TAG_file_typei",
    0x2a: "DW_TAG_friend",
    0x2b: "DW_TAG_namelist",
    0x2c: "DW_TAG_namelist_item",
    0x2d: "DW_TAG_packed_type",
    0x2e: "DW_TAG_subprogram",
    0x2f: "DW_TAG_template_type_parameter",
    0x30: "DW_TAG_template_value_parameter",
    0x31: "DW_TAG_thrown_type",
    0x32: "DW_TAG_try_block",
    0x33: "DW_TAG_variant_part",
    0x34: "DW_TAG_variable",
    0x35: "DW_TAG_volatile_type",
    0x36: "DW_TAG_dwarf_procedure",
    0x37: "DW_TAG_restrict_type",
    0x38: "DW_TAG_interface_type",
    0x39: "DW_TAG_namespace",
    0x3a: "DW_TAG_imported_module",
    0x3b: "DW_TAG_unspecified_type",
    0x3c: "DW_TAG_partial_unit",
    0x3d: "DW_TAG_imported_unit",
    0x3f: "DW_TAG_condition",
    0x40: "DW_TAG_shared_type",
    0x41: "DW_TAG_darray_type",
    0x42: "DW_TAG_aarray_type",
    0x43: "DW_TAG_delegate_type",
    0x4080: "DW_TAG_lo_user",
    0xffff: "DW_TAG_hi_user"
    ];

enum
{
    DW_CHILDREN_no			= 0x00,
    DW_CHILDREN_yes			= 0x01
}

enum
{
    DW_AT_sibling			= 0x01,
    DW_AT_location			= 0x02,
    DW_AT_name				= 0x03,
    DW_AT_ordering			= 0x09,
    DW_AT_byte_size			= 0x0b,
    DW_AT_bit_offset			= 0x0c,
    DW_AT_bit_size			= 0x0d,
    DW_AT_stmt_list			= 0x10,
    DW_AT_low_pc			= 0x11,
    DW_AT_high_pc			= 0x12,
    DW_AT_language			= 0x13,
    DW_AT_discr				= 0x15,
    DW_AT_discr_value			= 0x16,
    DW_AT_visibility			= 0x17,
    DW_AT_import			= 0x18,
    DW_AT_string_length			= 0x19,
    DW_AT_common_reference		= 0x1a,
    DW_AT_comp_dir			= 0x1b,
    DW_AT_const_value			= 0x1c,
    DW_AT_containing_type		= 0x1d,
    DW_AT_default_value			= 0x1e,
    DW_AT_inline			= 0x20,
    DW_AT_is_optional			= 0x21,
    DW_AT_lower_bound			= 0x22,
    DW_AT_producer			= 0x25,
    DW_AT_prototyped			= 0x27,
    DW_AT_return_addr			= 0x2a,
    DW_AT_start_scope			= 0x2c,
    DW_AT_bit_stride			= 0x2e,
    DW_AT_upper_bound			= 0x2f,
    DW_AT_abstract_origin		= 0x31,
    DW_AT_accessibility			= 0x32,
    DW_AT_address_class			= 0x33,
    DW_AT_artificial			= 0x34,
    DW_AT_base_types			= 0x35,
    DW_AT_calling_convention		= 0x36,
    DW_AT_count				= 0x37,
    DW_AT_data_member_location		= 0x38,
    DW_AT_decl_column			= 0x39,
    DW_AT_decl_file			= 0x3a,
    DW_AT_decl_line			= 0x3b,
    DW_AT_declaration			= 0x3c,
    DW_AT_discr_list			= 0x3d,
    DW_AT_encoding			= 0x3e,
    DW_AT_external			= 0x3f,
    DW_AT_frame_base			= 0x40,
    DW_AT_friend			= 0x41,
    DW_AT_identifier_case		= 0x42,
    DW_AT_macro_info			= 0x43,
    DW_AT_namelist_item			= 0x44,
    DW_AT_priority			= 0x45,
    DW_AT_segment			= 0x46,
    DW_AT_specification			= 0x47,
    DW_AT_static_link			= 0x48,
    DW_AT_type				= 0x49,
    DW_AT_use_location			= 0x4a,
    DW_AT_variable_parameter		= 0x4b,
    DW_AT_virtuality			= 0x4c,
    DW_AT_vtable_elem_location		= 0x4d,
    DW_AT_allocated			= 0x4e,
    DW_AT_associated			= 0x4f,
    DW_AT_data_location			= 0x50,
    DW_AT_byte_stride			= 0x51,
    DW_AT_entry_pc			= 0x52,
    DW_AT_use_UTF8			= 0x53,
    DW_AT_extension			= 0x54,
    DW_AT_ranges			= 0x55,
    DW_AT_trampoline			= 0x56,
    DW_AT_call_column			= 0x57,
    DW_AT_call_file			= 0x58,
    DW_AT_call_line			= 0x59,
    DW_AT_description			= 0x5a,
    DW_AT_binary_scale			= 0x5b,
    DW_AT_decimal_scale			= 0x5c,
    DW_AT_small				= 0x5d,
    DW_AT_decimal_sign			= 0x5e,
    DW_AT_digit_count			= 0x5f,
    DW_AT_picture_string		= 0x60,
    DW_AT_mutable			= 0x61,
    DW_AT_threads_scaled		= 0x62,
    DW_AT_explicit			= 0x63,
    DW_AT_object_pointer		= 0x64,
    DW_AT_endianity			= 0x65,
    DW_AT_elemental			= 0x66,
    DW_AT_pure				= 0x67,
    DW_AT_recursive			= 0x68,
    DW_AT_lo_user			= 0x2000,
    DW_AT_hi_user			= 0x3fff
}

string attrNames[] = [
    0x01: "DW_AT_sibling",
    0x02: "DW_AT_location",
    0x03: "DW_AT_name",
    0x09: "DW_AT_ordering",
    0x0b: "DW_AT_byte_size",
    0x0c: "DW_AT_bit_offset",
    0x0d: "DW_AT_bit_size",
    0x10: "DW_AT_stmt_list",
    0x11: "DW_AT_low_pc",
    0x12: "DW_AT_high_pc",
    0x13: "DW_AT_language",
    0x15: "DW_AT_discr",
    0x16: "DW_AT_discr_value",
    0x17: "DW_AT_visibility",
    0x18: "DW_AT_import",
    0x19: "DW_AT_string_length",
    0x1a: "DW_AT_common_reference",
    0x1b: "DW_AT_comp_dir",
    0x1c: "DW_AT_const_value",
    0x1d: "DW_AT_containing_type",
    0x1e: "DW_AT_default_value",
    0x20: "DW_AT_inline",
    0x21: "DW_AT_is_optional",
    0x22: "DW_AT_lower_bound",
    0x25: "DW_AT_producer",
    0x27: "DW_AT_prototyped",
    0x2a: "DW_AT_return_addr",
    0x2c: "DW_AT_start_scope",
    0x2e: "DW_AT_bit_stride",
    0x2f: "DW_AT_upper_bound",
    0x31: "DW_AT_abstract_origin",
    0x32: "DW_AT_accessibility",
    0x33: "DW_AT_address_class",
    0x34: "DW_AT_artificial",
    0x35: "DW_AT_base_types",
    0x36: "DW_AT_calling_convention",
    0x37: "DW_AT_count",
    0x38: "DW_AT_data_member_location",
    0x39: "DW_AT_decl_column",
    0x3a: "DW_AT_decl_file",
    0x3b: "DW_AT_decl_line",
    0x3c: "DW_AT_declaration",
    0x3d: "DW_AT_discr_list",
    0x3e: "DW_AT_encoding",
    0x3f: "DW_AT_external",
    0x40: "DW_AT_frame_base",
    0x41: "DW_AT_friend",
    0x42: "DW_AT_identifier_case",
    0x43: "DW_AT_macro_info",
    0x44: "DW_AT_namelist_item",
    0x45: "DW_AT_priority",
    0x46: "DW_AT_segment",
    0x47: "DW_AT_specification",
    0x48: "DW_AT_static_link",
    0x49: "DW_AT_type",
    0x4a: "DW_AT_use_location",
    0x4b: "DW_AT_variable_parameter",
    0x4c: "DW_AT_virtuality",
    0x4d: "DW_AT_vtable_elem_location",
    0x4e: "DW_AT_allocated",
    0x4f: "DW_AT_associated",
    0x50: "DW_AT_data_location",
    0x51: "DW_AT_byte_stride",
    0x52: "DW_AT_entry_pc",
    0x53: "DW_AT_use_UTF8",
    0x54: "DW_AT_extension",
    0x55: "DW_AT_ranges",
    0x56: "DW_AT_trampoline",
    0x57: "DW_AT_call_column",
    0x58: "DW_AT_call_file",
    0x59: "DW_AT_call_line",
    0x5a: "DW_AT_description",
    0x5b: "DW_AT_binary_scale",
    0x5c: "DW_AT_decimal_scale",
    0x5d: "DW_AT_small",
    0x5e: "DW_AT_decimal_sign",
    0x5f: "DW_AT_digit_count",
    0x60: "DW_AT_picture_string",
    0x61: "DW_AT_mutable",
    0x62: "DW_AT_threads_scaled",
    0x63: "DW_AT_explicit",
    0x64: "DW_AT_object_pointer",
    0x65: "DW_AT_endianity",
    0x66: "DW_AT_elemental",
    0x67: "DW_AT_pure",
    0x68: "DW_AT_recursive",
    0x2000: "DW_AT_lo_user",
    0x3fff: "AT_hi_user"
    ];

enum
{
    DW_FORM_addr			= 0x01,
    DW_FORM_block2			= 0x03,
    DW_FORM_block4			= 0x04,
    DW_FORM_data2			= 0x05,
    DW_FORM_data4			= 0x06,
    DW_FORM_data8			= 0x07,
    DW_FORM_string			= 0x08,
    DW_FORM_block			= 0x09,
    DW_FORM_block1			= 0x0a,
    DW_FORM_data1			= 0x0b,
    DW_FORM_flag			= 0x0c,
    DW_FORM_sdata			= 0x0d,
    DW_FORM_strp			= 0x0e,
    DW_FORM_udata			= 0x0f,
    DW_FORM_ref_addr			= 0x10,
    DW_FORM_ref1			= 0x11,
    DW_FORM_ref2			= 0x12,
    DW_FORM_ref4			= 0x13,
    DW_FORM_ref8			= 0x14,
    DW_FORM_ref_udata			= 0x15,
    DW_FORM_indirect			= 0x16
}

enum
{
    DW_OP_addr				= 0x03,
    DW_OP_deref				= 0x06,
    DW_OP_const1u			= 0x08,
    DW_OP_const1s			= 0x09,
    DW_OP_const2u			= 0x0a,
    DW_OP_const2s			= 0x0b,
    DW_OP_const4u			= 0x0c,
    DW_OP_const4s			= 0x0d,
    DW_OP_const8u			= 0x0e,
    DW_OP_const8s			= 0x0f,
    DW_OP_constu			= 0x10,
    DW_OP_consts			= 0x11,
    DW_OP_dup				= 0x12,
    DW_OP_drop				= 0x13,
    DW_OP_over				= 0x14,
    DW_OP_pick				= 0x15,
    DW_OP_swap				= 0x16,
    DW_OP_rot				= 0x17,
    DW_OP_xderef			= 0x18,
    DW_OP_abs				= 0x19,
    DW_OP_and				= 0x1a,
    DW_OP_div				= 0x1b,
    DW_OP_minus				= 0x1c,
    DW_OP_mod				= 0x1d,
    DW_OP_mul				= 0x1e,
    DW_OP_neg				= 0x1f,
    DW_OP_not				= 0x20,
    DW_OP_or				= 0x21,
    DW_OP_plus				= 0x22,
    DW_OP_plus_uconst			= 0x23,
    DW_OP_shl				= 0x24,
    DW_OP_shr				= 0x25,
    DW_OP_shra				= 0x26,
    DW_OP_xor				= 0x27,
    DW_OP_skip				= 0x2f,
    DW_OP_bra				= 0x28,
    DW_OP_eq				= 0x29,
    DW_OP_ge				= 0x2a,
    DW_OP_gt				= 0x2b,
    DW_OP_le				= 0x2c,
    DW_OP_lt				= 0x2d,
    DW_OP_ne				= 0x2e,
    DW_OP_lit0				= 0x30,
    DW_OP_lit1				= 0x31,
    DW_OP_lit31				= 0x4f,
    DW_OP_reg0				= 0x50,
    DW_OP_reg1				= 0x51,
    DW_OP_reg31				= 0x6f,
    DW_OP_breg0				= 0x70,
    DW_OP_breg1				= 0x71,
    DW_OP_breg31			= 0x8f,
    DW_OP_regx				= 0x90,
    DW_OP_fbreg				= 0x91,
    DW_OP_bregx				= 0x92,
    DW_OP_piece				= 0x93,
    DW_OP_deref_size			= 0x94,
    DW_OP_xderef_size			= 0x95,
    DW_OP_nop				= 0x96,
    DW_OP_push_object_address		= 0x97,
    DW_OP_call2				= 0x98,
    DW_OP_call4				= 0x99,
    DW_OP_call_ref			= 0x9a,
    DW_OP_form_tls_address		= 0x9b,
    DW_OP_call_frame_cfa		= 0x9c,
    DW_OP_bit_piece			= 0x9d,
    DW_OP_GNU_push_tls_address		= 0xe0,
    DW_OP_lo_user			= 0xe0,
    DW_OP_hi_user			= 0xff,
}
int DW_OP_lit(int n)
{
    return DW_OP_lit0 + n;
}
int DW_OP_reg(int n)
{
    return DW_OP_reg0 + n;
}
int DW_OP_breg(int n)
{
    return DW_OP_breg0 + n;
}

enum
{
    DW_ATE_address			= 0x01,
    DW_ATE_boolean			= 0x02,
    DW_ATE_complex_float		= 0x03,
    DW_ATE_float			= 0x04,
    DW_ATE_signed			= 0x05,
    DW_ATE_signed_char			= 0x06,
    DW_ATE_unsigned			= 0x07,
    DW_ATE_unsigned_char		= 0x08,
    DW_ATE_imaginary_float		= 0x09,
    DW_ATE_packed_decimal		= 0x0a,
    DW_ATE_numeric_string		= 0x0b,
    DW_ATE_edited			= 0x0c,
    DW_ATE_signed_fixed			= 0x0d,
    DW_ATE_unsigned_fixed		= 0x0e,
    DW_ATE_decimal_float		= 0x0f,
    DW_ATE_lo_user			= 0x80,
    DW_ATE_hi_user			= 0xff,
}

enum
{
    DW_DS_unsigned			= 0x01,
    DW_DS_leading_overpunch		= 0x02,
    DW_DS_trailing_overpunch		= 0x03,
    DW_DS_leading_separate		= 0x04,
    DW_DS_trailing_separate		= 0x05,
}

enum
{
    DW_END_default			= 0x00,
    DW_END_big				= 0x01,
    DW_END_little			= 0x02,
    DW_END_lo_user			= 0x40,
    DW_END_hi_user			= 0xff,
}

enum
{
    DW_ACCESS_public			= 0x01,
    DW_ACCESS_protected			= 0x02,
    DW_ACCESS_private			= 0x03,
}

enum
{
    DW_VIS_local			= 0x01,
    DW_VIS_exported			= 0x02,
    DW_VIS_qualified			= 0x03,
}

enum
{
    DW_VIRTUALITY_none			= 0x00,
    DW_VIRTUALITY_virtual		= 0x01,
    DW_VIRTUALITY_pure_virtual		= 0x02,
}

enum
{
    DW_LANG_C89				= 0x0001,
    DW_LANG_C				= 0x0002,
    DW_LANG_Ada83			= 0x0003,
    DW_LANG_C_plus_plus			= 0x0004,
    DW_LANG_Cobol74			= 0x0005,
    DW_LANG_Cobol85			= 0x0006,
    DW_LANG_Fortran77			= 0x0007,
    DW_LANG_Fortran90			= 0x0008,
    DW_LANG_Pascal83			= 0x0009,
    DW_LANG_Modula2			= 0x000a,
    DW_LANG_Java			= 0x000b,
    DW_LANG_C99				= 0x000c,
    DW_LANG_Ada95			= 0x000d,
    DW_LANG_Fortran95			= 0x000e,
    DW_LANG_PLI				= 0x000f,
    DW_LANG_ObjC			= 0x0010,
    DW_LANG_ObjC_plus_plus		= 0x0011,
    DW_LANG_UPC				= 0x0012,
    DW_LANG_D				= 0x0013,
    DW_LANG_lo_user			= 0x8000,
    DW_LANG_hi_user			= 0xffff,
}

enum
{
    DW_ADDR_none			= 0
}

enum
{
    DW_ID_case_sensitive		= 0x00,
    DW_ID_up_case			= 0x01,
    DW_ID_down_case			= 0x02,
    DW_ID_case_insensitive		= 0x03,
}

enum
{
    DW_CC_normal			= 0x01,
    DW_CC_program			= 0x02,
    DW_CC_nocall			= 0x03,
    DW_CC_lo_user			= 0x40,
    DW_CC_hi_user			= 0xff,
}

enum
{
    DW_INL_not_inlined			= 0x00,
    DW_INL_inlined			= 0x01,
    DW_INL_declared_not_inlined		= 0x02,
    DW_INL_declared_inlined		= 0x03,
}

enum
{
    DW_ORD_row_major			= 0x00,
    DW_ORD_col_major			= 0x01,
}

enum
{
    DW_DSC_label			= 0x00,
    DW_DSC_range			= 0x01,
}

enum
{
    DW_LNS_copy				= 0x01,
    DW_LNS_advance_pc			= 0x02,
    DW_LNS_advance_line			= 0x03,
    DW_LNS_set_file			= 0x04,
    DW_LNS_set_column			= 0x05,
    DW_LNS_negate_stmt			= 0x06,
    DW_LNS_set_basic_block		= 0x07,
    DW_LNS_const_add_pc			= 0x08,
    DW_LNS_fixed_advance_pc		= 0x09,
    DW_LNS_set_prologue_end		= 0x0a,
    DW_LNS_set_epilogue_begin		= 0x0b,
    DW_LNS_set_isa			= 0x0c,
    DW_LNE_end_sequence			= 0x01,
    DW_LNE_set_address			= 0x02,
    DW_LNE_define_file			= 0x03,
    DW_LNE_lo_user			= 0x80,
    DW_LNE_hi_user			= 0xff,
}

enum
{
    DW_MACINFO_define			= 0x01,
    DW_MACINFO_undef			= 0x02,
    DW_MACINFO_start_file		= 0x03,
    DW_MACINFO_end_file			= 0x04,
    DW_MACINFO_vendor_ext		= 0xff,
}

enum
{
    DW_CFA_advance_loc			= 0x40,
    DW_CFA_offset			= 0x80,
    DW_CFA_restore			= 0xc0,
    DW_CFA_nop				= 0x00,
    DW_CFA_set_loc			= 0x01,
    DW_CFA_advance_loc1			= 0x02,
    DW_CFA_advance_loc2			= 0x03,
    DW_CFA_advance_loc4			= 0x04,
    DW_CFA_offset_extended		= 0x05,
    DW_CFA_restore_extended		= 0x06,
    DW_CFA_undefined			= 0x07,
    DW_CFA_same_value			= 0x08,
    DW_CFA_register			= 0x09,
    DW_CFA_remember_state		= 0x0a,
    DW_CFA_restore_state		= 0x0b,
    DW_CFA_def_cfa			= 0x0c,
    DW_CFA_def_cfa_register		= 0x0d,
    DW_CFA_def_cfa_offset		= 0x0e,
    DW_CFA_def_cfa_expression		= 0x0f,
    DW_CFA_expression			= 0x10,
    DW_CFA_offset_extended_sf		= 0x11,
    DW_CFA_def_cfa_sf			= 0x12,
    DW_CFA_def_cfa_offset_sf		= 0x13,
    DW_CFA_val_offset			= 0x14,
    DW_CFA_val_offset_sf		= 0x15,
    DW_CFA_val_expression		= 0x16,
    DW_CFA_lo_user			= 0x1c,
    DW_CFA_hi_user			= 0x3f,

    // Extensions
    DW_CFA_MIPS_advance_loc8	= 0x1d,
    DW_CFA_GNU_window_save		= 0x2d,
    DW_CFA_GNU_args_size		= 0x2e,
    DW_CFA_GNU_negative_offset_extended	= 0x2f,
}

class DwarfFile: public DebugInfo
{
    this(Objfile obj)
    {
	obj_ = obj;

	if (obj_.hasSection(".debug_str"))
	    strtab_ = obj_.readSection(".debug_str");

	// Read .debug_pubnames if present
	if (obj_.hasSection(".debug_pubnames")) {
	    char[] pubnames = obj_.readSection(".debug_pubnames");
	    char* p = &pubnames[0], pEnd = p + pubnames.length;

	    while (p < pEnd) {
		bool is64;
		ulong len = parseInitialLength(p, is64);
		uint ver = parseUShort(p);

		NameSet set;
		set.cuOffset = parseOffset(p, is64);
		parseLength(p, is64);
		for (;;) {
		    ulong off = parseOffset(p, is64);
		    if (!off)
			break;
		    string name = parseString(p);
		    if (name in set.names)
			set.names[name] ~= off;
		    else
			set.names[name] = [off];
		    if (name == "foo.foo")
		    writefln("%s = %d (cu %d)", name, off, set.cuOffset);
		}
		pubnames_ ~= set;
	    }
	}

	// Read .debug_pubtypes if present
	if (obj_.hasSection(".debug_pubtypes")) {
	    char[] pubtypes = obj_.readSection(".debug_pubtypes");
	    char* p = &pubtypes[0], pEnd = p + pubtypes.length;

	    while (p < pEnd) {
		bool is64;
		ulong len = parseInitialLength(p, is64);
		uint ver = parseUShort(p);

		NameSet set;
		set.cuOffset = parseOffset(p, is64);
		parseLength(p, is64);
		for (;;) {
		    ulong off = parseOffset(p, is64);
		    if (!off)
			break;
		    string name = parseString(p);
		    if (name in set.names)
			set.names[name] ~= off;
		    else
			set.names[name] = [off];
		    //writefln("%s = %d (cu %d)", name, off, set.cuOffset);
		}

	    }
	}

	// Read .debug_aranges if present
	CompilationUnit cu;
	if (obj_.hasSection(".debug_aranges")) {
	    char[] aranges = obj_.readSection(".debug_aranges");
	    char* p = aranges.ptr, pEnd = p + aranges.length;
	    ulong offset = obj_.offset;

	    while (p < pEnd) {
		bool is64;
		ulong len = parseInitialLength(p, is64);
		uint ver = parseUShort(p);

		cu = new CompilationUnit(this);
		cu.offset = parseOffset(p, is64);
		cu.addressSize = parseUByte(p);
		cu.segmentSize = parseUByte(p);

		// Undocumented: need to align to next multiple of
		// 2 * address size
		ulong a = cu.addressSize * 2;
		if ((p - &aranges[0]) % a) {
		    p += a - ((p - &aranges[0]) % a);
		}

		ulong start, length;
		for (;;) {
		    start = parseAddress(p);
		    length = parseAddress(p);
		    if (start == 0 && length == 0)
			break;
		    start += offset;
		    cu.addresses ~= AddressRange(start, start + length);
		}
		//writefln("cu offset %d = %#x", cu.offset, cast(ulong) cu);
		compilationUnits_[cu.offset] = cu;
	    }
	}

	/*
	 * Scan through the .debug_info section and add partial
	 * compilation units for everything we didn't handle when
	 * processing .debug_aranges.
	 */
	char[] debugInfo = debugSection(".debug_info");
	char* p = &debugInfo[0], ep = p + debugInfo.length;
	bool is64;

	do {
	    cu = new CompilationUnit(this);
	    cu.offset = p - &debugInfo[0];
	    auto len = parseInitialLength(p, is64);
	    auto pNext = p + len;
	    auto ver = parseUShort(p);
	    parseOffset(p, is64);
	    cu.addressSize = parseUByte(p);
	    cu.segmentSize = 0;
	    if (!(cu.offset in compilationUnits_))
		compilationUnits_[cu.offset] = cu;
	    p = pNext;
	} while (p < ep);

	parseDebugFrame();
    }

    static bool hasDebug(Objfile obj)
    {
	if (obj.hasSection(".debug_line")
	    && obj.hasSection(".debug_info")
	    && obj.hasSection(".debug_abbrev"))
	    return true;
	return false;
    }

    override {
	// Scope compliance
	string[] contents(MachineState)
	{
	    string[] res;
	    foreach (ns; pubnames_) {
		if (ns.cuOffset in compilationUnits_) {
		    res ~= ns.names.keys;
		}
	    }
	    return res;
	}
	DebugItem lookup(string name, MachineState)
	{
	    foreach (ns; pubnames_) {
		if (ns.cuOffset in compilationUnits_) {
		    CompilationUnit cu = compilationUnits_[ns.cuOffset];
		    if (name in ns.names) {
			cu.loadDIE;
			foreach (dieOff; ns.names[name]) {
			    DIE die = cu.dieMap[dieOff];
			    if (auto val = die.debugItem)
				return val;
			}
		    }
		}
	    }
	    return null;
	}
	Type lookupStruct(string name)
	{
	    /*
	     * Brute force all CUs.
	     */
	    foreach (cu; compilationUnits_) {
		cu.loadDIE;
		foreach (d; cu.die.children_) {
		    if (d.tag == DW_TAG_structure_type && d.name == name) {
			return d.toType;
		    }
		}
	    }
	    return null;
	}
        // TODO: unimplemented ??
	Type lookupUnion(string name) { return null; }
	Type lookupTypedef(string name) { return null; }

	// DebugInfo compliance
	Language findLanguage(ulong address)
	{
	    CompilationUnit cu;
	    if (findCU(address, cu))
		return cu.lang;
	    return null;
	}

	bool findLineByAddress(ulong address, out LineEntry[] res)
	{
	    bool found = false;
	    LineEntry lastEntry;
	    LineEntry best[2];

	    bool processEntry(LineEntry* le)
	    {
		if (!le) {
		    lastEntry.address = ~0;
		    return false;
		}
		debug (line)
		    writefln("%s:%d 0x%x", le.fullname, le.line, le.address);
		if (le.address > lastEntry.address) {
		    if (lastEntry.address <= address
			&& address <= le.address) {
			if (!found || (address - lastEntry.address < address - best[0].address)) {
			    best[0] = lastEntry;
			    best[1] = *le;
			    found = true;
		        }
		    }
		}
		lastEntry = *le;
		return false;
	    }

	    debug (line)
		writefln("finding 0x%x", address);
	    CompilationUnit cu;
	    if (findCU(address, cu)) {
		auto lineOffset = cu.die[DW_AT_stmt_list].ul;
		char[] lines = debugSection(".debug_line");
		char* p = &lines[lineOffset];
		lastEntry.address = ~0;
		parseLineTable(p, &processEntry);
		if (found) {
		    res.length = 2;
		    res[] = best[];
		    return true;
		}
	    }
	    return false;
	}

	bool findLineByName(string file, int line, out LineEntry[] res)
	{
	    bool found = false;

	    bool processEntry(LineEntry* le)
	    {
		if (!le)
		    return false;
		if ((le.name == file || le.fullname == file)
		    && le.line == line) {
		    found = true;
		    res ~= *le;
		}
		return false;
	    }

	    char[] lines = debugSection(".debug_line");
	    char* p = &lines[0], pEnd = p + lines.length;
	    while (p < pEnd)
		parseLineTable(p, &processEntry);
	    return found;
	}

	string[] findSourceFiles()
	{
	    bool[string] fileset;

	    bool processEntry(LineEntry* le)
	    {
		if (!le)
		    return false;
		if (!(le.fullname in fileset))
		    fileset[le.fullname] = true;
		return false;
	    }

	    char[] lines = debugSection(".debug_line");
	    char* p = &lines[0], pEnd = p + lines.length;
	    while (p < pEnd)
		parseLineTable(p, &processEntry);

            string[] abs;
            abs.length = fileset.length;
            foreach(i, file; fileset.keys)
                abs[i] = disambiguateRelativeFile(file);
            return abs;
	}

	bool findLineByFunction(string func, out LineEntry[] res)
	{
	    foreach (ns; pubnames_) {
		if (ns.cuOffset in compilationUnits_) {
		    CompilationUnit cu = compilationUnits_[ns.cuOffset];
		    if (func in ns.names) {
			cu.loadDIE;
			foreach (dieOff; ns.names[func]) {
			    DIE die = cu.dieMap[dieOff];
			    if (die.tag == DW_TAG_subprogram) {
				LineEntry[] le;
				Function f = cast(Function) die.debugItem;
				auto lpc = f.address;
				if (findLineByAddress(lpc, le))
				    res ~= le[1];
			    }
			}
		    }
		} else {
		    continue;
		}
	    }

	    return res.length > 0;
	}

	bool findFrameBase(MachineState state, out Location loc)
	{
	    auto pc = state.pc;
	    CompilationUnit cu;
	    DIE func;
	    if (findSubprogram(pc, false, cu, func)) {
		auto l = func[DW_AT_frame_base];
		if (l) {
		    auto dwloc = new DwarfLocation(cu, l, 1);
		    if (dwloc.evalLocation(state, loc)) {
			/*
			 * XXX LLVM generates useless values for
			 * DW_AT_frame_base, at least for x86. Try to
			 * detect this and get the frame value from
			 * the frame unwinder.
			 */
			RegisterLocation rloc = cast(RegisterLocation) loc;
			if (rloc) {
			    foreach (fde; fdes_) {
				if (fde.contains(pc)) {
				    loc = fde.frameLocation(state);
				    return true;
				}
			    }

			    /*
			     * We got nothing from the unwinder -
			     * return the register value as a memory
			     * location.
			     */
			    ulong regval =
				state.readInteger(rloc.readValue(state));
			    loc = new MemoryLocation(regval, 1);
			}
			return true;
		    }
		    return false;
		}
	    }
	    return false;
	}

	Function findFunction(ulong pc)
	{
	    CompilationUnit cu;
	    DIE func;
	    if (findSubprogram(pc, true, cu, func))
		return cast(Function) func.debugItem;
	    return null;
	}

	MachineState unwind(MachineState state)
	{
	    auto pc = state.pc;

	    CompilationUnit cu;
	    DIE func;
	    if (findSubprogram(pc, true, cu, func)) {
		if (func.tag == DW_TAG_inlined_subroutine) {
		    foreach (a; func.addresses) {
			if (a.contains(pc)) {
			    MachineState newState = state.dup;
			    newState.pc = state.findJump(pc, a.end);
			    return newState;
			}
		    }
		}
	    }

	    foreach (fde; fdes_)
		if (fde.contains(pc))
		    return fde.unwind(state);
	    return null;
	}
    }

private:
    char[] debugSection(string name)
    {
	if (name in debugSections_) {
	    return debugSections_[name];
	} else {
	    debugSections_[name] = obj_.readSection(name);
	    return debugSections_[name];
	}
    }

    // GCC and dmd don't output includeDirectories so fe.fullname is a
    // relative path, try to find absolute path in compilation units
    string disambiguateRelativeFile(string path) {
        if (std.path.isabs(path))
            return path;

        string[] cumatches;
        foreach(cu; compilationUnits_.byValue) {
            if (cu.sourceName != path)
                continue;
            auto npath = std.path.join(cu.compDir, cu.sourceName);
            if (!canFind(cumatches, npath))
                cumatches ~= npath;
        }

        if (cumatches.empty) {
            std.stdio.stderr.writefln("warning: can't find absolute path for %s", path);
            return path;
        } else if (cumatches.length == 1) {
            return cumatches[0];
        } else {
            string match;
            foreach(m; cumatches) {
                if (!(std.file.exists(m) && std.file.isFile(m)))
                    continue;
                match = m;
                break;
            }
            if (match.empty)
                match = cumatches[0];
            std.stdio.stderr.writefln("warning: ambiguous source file, took %s, but could be any of %s",
                                      match, cumatches);
            return match;
        }
    }

    void parseDebugFrame()
    {
	char[] debugFrame = debugSection(".debug_frame");
	char* pStart = &debugFrame[0];
	char* pEnd = pStart + debugFrame.length;
	char* p = pStart;
	ulong offset = obj_.offset;

	CIE[ulong] cies;

	while (p < pEnd) {
	    bool is64;
	    ulong off = p - pStart;
	    auto len = parseInitialLength(p, is64);
	    auto entryStart = p;
	    auto cie_id = parseOffset(p, is64);

	    if ((is64 && cie_id == 0xffffffffffffffff)
		|| (!is64 && cie_id == 0xffffffff)) {
		// CIE
		CIE cie = new CIE;
		auto ver = parseUByte(p);
		auto augmentation = parseString(p);
		cie.codeAlign = to!uint(parseULEB128(p));
		cie.dataAlign = to!int(parseSLEB128(p));
		cie.returnAddress = to!uint(parseULEB128(p));
		cie.instructionStart = p;
		cie.instructionEnd = entryStart + len;
		cies[off] = cie;
	    } else {
		// FDE
		FDE fde = new FDE;
		fde.dw = this;
		fde.cie = cies[cie_id];
		fde.initialLocation = parseAddress(p) + offset;
		fde.addressRange = parseAddress(p);
		fde.instructionStart = p;
		fde.instructionEnd = entryStart + len;
		fdes_ ~= fde;
	    }
	    p = entryStart + len;
	}
    }

    void parseCompilationUnit(CompilationUnit cu, ref char* p)
    {
	bool is64;
	size_t len;
	char* base = p;
	char* pNext;

	len = parseInitialLength(p, is64);
	pNext = p + len;

	uint ver = parseUShort(p);
	ulong abbrevOffset = parseOffset(p, is64);
	uint addrlen = parseUByte(p);

	char[] abbrev = debugSection(".debug_abbrev");
	char* abbrevp = &abbrev[abbrevOffset];
	char*[ulong] abbrevTable;
	for (;;) {
	    ulong code = parseULEB128(abbrevp);
	    if (!code)
		break;
	    abbrevTable[code] = abbrevp;

	    // Skip entry
	    parseULEB128(abbrevp); // tag
	    abbrevp++;		   // hasChildren
	    for (;;) {
		ulong at = parseULEB128(abbrevp);
		ulong form = parseULEB128(abbrevp);
		if (!at)
		    break;
	    }
	}

	ulong off = p - base;
	ulong abbrevCode = parseULEB128(p);
	if (abbrevCode == 0)
	    return;

	cu.is64 = is64;
	cu.die = new DIE(cu, null, base, p, abbrevCode,
			 abbrevTable, addrlen, strtab_);
	cu.dieMap[off] = cu.die;
    }

    void parseLineTable(ref char* p, bool delegate(LineEntry*) dg)
    {
	struct DwarfLineEntry {
	    ulong address;
	    uint file;
	    uint line;
	    uint column;
	    bool isStatement;
	    bool basicBlock;
	    bool endSequence;
	    bool prologueEnd;
	    bool epilogueBegin;
	    int isa;
	}

	struct FileEntry {
	    string fullname;
	    char* name;
	    uint directoryIndex;
	    ulong modificationTime;
	    ulong length;
	}

	bool is64;
	size_t len;
	char* pEnd, pEndHeader;
	ulong offset = obj_.offset;

	len = parseInitialLength(p, is64);
	pEnd = p + len;
	uint ver = parseUShort(p);
	ulong headerLength = parseLength(p, is64);
	pEndHeader = p + headerLength;
	uint instructionLength = parseUByte(p);
	bool defaultIsStatement = parseUByte(p) != 0;
	int lineBase = parseSByte(p);
	uint lineRange = parseUByte(p);
	ubyte standardOpcodeLengths[];
	uint opcodeBase = parseUByte(p);
	standardOpcodeLengths.length = opcodeBase;
	for (int i = 1; i < opcodeBase; i++)
	    standardOpcodeLengths[i] = parseUByte(p);

	char* includeDirectories[];
	while (*p) {
	    includeDirectories ~= p;
	    skipString(p);
	}
	p++;

	FileEntry fileNames[];
	while (*p) {
	    char* name = p;
	    skipString(p);
	    uint di = to!uint(parseULEB128(p));
	    ulong mt = parseULEB128(p);
	    ulong fl = parseULEB128(p);
	    fileNames ~= FileEntry(null, name, di, mt, fl);
	}
	p++;

	if (p != pEndHeader)
	    throw new Exception("unexpected bytes in line table header");

	DwarfLineEntry init, le;

	init.address = 0;
	init.file = 1;
	init.line = 1;
	init.column = 0;
	init.isStatement = defaultIsStatement;
	init.basicBlock = false;
	init.endSequence = false;
	init.prologueEnd = false;
	init.epilogueBegin = false;
	init.isa = 0;

	le = init;

	int specialOpcodeAddressIncrement(ubyte op)
	{
	    op -= opcodeBase;
	    return (op / lineRange) * instructionLength;
	}

	int specialOpcodeLineIncrement(ubyte op)
	{
	    op -= opcodeBase;
	    return lineBase + (op % lineRange);
	}

	bool processRow(DwarfLineEntry* le)
	{
	    FileEntry* fe = &fileNames[le.file - 1];
	    if (fe.fullname == null) {
		if (fe.directoryIndex) {
		    auto dir =
			to!string(includeDirectories[fe.directoryIndex - 1]);
		    fe.fullname = std.path.join(dir, to!string(fe.name));
		} else {
		    fe.fullname = disambiguateRelativeFile(to!string(fe.name));
		}
	    }

	    LineEntry dle;
	    dle.address = le.address + offset;
	    dle.name = to!string(fe.name);
	    dle.fullname = fe.fullname;
	    dle.line = le.line;
	    dle.column = le.column;
	    dle.isStatement = le.isStatement;
	    dle.basicBlock = le.basicBlock;
	    dle.endSequence = le.endSequence;
	    dle.prologueEnd = le.prologueEnd;
	    dle.epilogueBegin = le.epilogueBegin;
	    return dg(&dle);
	}

	debug (line)
	    writefln("opcodeBase=%d, lineBase=%d, lineRange=%d",
		     opcodeBase, lineBase, lineRange);
	while (p < pEnd) {
	    ubyte op = parseUByte(p);
	    if (op >= opcodeBase) {
		debug (line)
		    writefln("%d:special opcode %d:%d",
			     op,
			     specialOpcodeAddressIncrement(op),
			     specialOpcodeLineIncrement(op));
		le.address += specialOpcodeAddressIncrement(op);
		le.line += specialOpcodeLineIncrement(op);
		if (processRow(&le))
		    return;
		le.basicBlock = false;
		le.prologueEnd = false;
		le.epilogueBegin = false;
		continue;
	    }
	    switch (op) {
	    case 0:
		debug (line)
		    writefln("%d:extended opcode", op);
		// Extended opcode
		uint oplen = to!uint(parseULEB128(p));
		char* pNext = p + oplen;
		switch (parseUByte(p)) {
		case DW_LNE_end_sequence:
		    debug (line)
			writefln(" %d:DW_LNE_end_sequence", op);
		    le.endSequence = true;
		    if (processRow(&le))
			return;
		    dg(null);
		    le = init;
		    break;

		case DW_LNE_set_address:
		    le.address = parseAddress(p);
		    debug (line)
			writefln(" %d:DW_LNE_set_address(0x%x)",
				 op, le.address);
		    break;

		case DW_LNE_define_file:
		    char* name = p;
		    skipString(p);
		    uint di = to!uint(parseULEB128(p));
		    ulong mt = parseULEB128(p);
		    ulong fl = parseULEB128(p);
		    fileNames ~= FileEntry(null, name, di, mt, fl);
		    debug (line)
			writefln(" %d:DW_LNE_define_file(%s)",
				 op, to!string(name));
		    break;

                default:
                    assert(0);
		}
		p = pNext;
		break;

	    case DW_LNS_copy:
		debug (line)
		    writefln("%d:DW_LNS_copy", op);
		if (processRow(&le))
		    return;
		le.basicBlock = false;
		le.prologueEnd = false;
		le.epilogueBegin = false;
		break;

	    case DW_LNS_advance_pc:
		le.address += instructionLength * parseULEB128(p);
		debug (line)
		    writefln("%d:DW_LNS_advance_pc(0x%x)", op, le.address);
		break;

	    case DW_LNS_advance_line:
		debug (line) {
		    char* pp = p;
		    writefln("%d:DW_LNS_advance_line(%d)",
			     op, *pp);
		}
		le.line += instructionLength * parseSLEB128(p);
		break;

	    case DW_LNS_set_file:
		le.file = to!uint(parseULEB128(p));
		debug (line)
		    writefln("%d:DW_LNS_set_file(%s)",
			     op, to!string(fileNames[le.file].name));
		break;

	    case DW_LNS_set_column:
		le.column = to!uint(parseULEB128(p));
		debug (line)
		    writefln("%d:DW_LNS_set_column(%s)", op, le.column);
		break;

	    case DW_LNS_negate_stmt:
		debug (line)
		    writefln("%d:DW_LNS_negate_stmt", op);
		le.isStatement = !le.isStatement;
		break;

	    case DW_LNS_set_basic_block:
		debug (line)
		    writefln("%d:DW_LNS_set_basic_block", op);
		le.basicBlock = true;
		break;

	    case DW_LNS_const_add_pc:
		debug (line)
		    writefln("%d:DW_LNS_add_pc(%d)", op,
			     specialOpcodeLineIncrement(255));
		le.address += specialOpcodeAddressIncrement(255);
		break;

	    case DW_LNS_fixed_advance_pc:
		debug (line) {
		    char* pp = p;
		    writefln("%d:DW_LNS_advance_pc", op, parseUShort(pp));
		}
		le.address += parseUShort(p);
		break;

	    case DW_LNS_set_prologue_end:
		debug (line)
		    writefln("%d:DW_LNS_set_prologue_end", op);
		le.prologueEnd = true;
		break;

	    case DW_LNS_set_epilogue_begin:
		debug (line)
		    writefln("%d:DW_LNS_set_epilogue_begin", op);
		le.epilogueBegin = true;
		break;

	    case DW_LNS_set_isa:
		debug (line)
		    writefln("%d:DW_LNS_set_isa", op);
		le.isa = to!uint(parseULEB128(p));
		break;

	    default:
		throw new Exception("Unexpected line table opcode");
	    }
	}
    }

    /**
     * Return the CU that contains the given address, if any.
     */
    bool findCU(ulong address, out CompilationUnit res)
    {
	foreach (cu; compilationUnits_) {
	    if (cu.contains(address)) {
		cu.loadDIE;
		res = cu;
		return true;
	    }
	}
	return false;
    }

    /**
     * Returh the CU and subprogram containing the given address.
     */
    bool findSubprogram(ulong address, bool findInline,
			out CompilationUnit cu, out DIE func)
    {
	if (findCU(address, cu))
	    return cu.findSubprogram(address, findInline, func);
	return false;
    }

    private ubyte parseUByte(ref char* p)
    {
	return *p++;
    }

    byte parseSByte(ref char* p)
    {
	byte v = *cast(byte*) p;
	p++;
	return v;
    }

    ushort parseUShort(ref char* p)
    {
	ushort v = *cast(ushort*) p;
	p += 2;
	return obj_.read(v);
    }

    short parseSShort(ref char* p)
    {
	return cast(short) parseUShort(p);
    }

    uint parseUInt(ref char* p)
    {
	uint v = *cast(uint*) p;
	p += 4;
	return obj_.read(v);
    }

    uint parseSInt(ref char* p)
    {
	return cast(int) parseUInt(p);
    }

    ulong parseULong(ref char* p)
    {
	ulong v = *cast(ulong*) p;
	p += 8;
	return obj_.read(v);
    }


    ulong parseSLong(ref char* p)
    {
	return cast(long) parseULong(p);
    }

    ulong parseOffset(ref char* p, bool is64)
    {
	if (is64)
	    return parseULong(p);
	else
	    return parseUInt(p);
    }

    ulong parseAddress(ref char* p)
    {
	if (obj_.is64)
	    return parseULong(p);
	else
	    return parseUInt(p);
    }

    ulong parseLength(ref char* p, bool is64)
    {
	if (is64)
	    return parseULong(p);
	else
	    return parseUInt(p);
    }

    void skipString(ref char* p)
    {
	while (*p)
	    p++;
	p++;
    }

    string parseString(ref char* p)
    {
	string v = to!string(p);
	skipString(p);
	return v;
    }

    size_t parseInitialLength(ref char* p, ref bool is64)
    {
	uint v = parseUInt(p);
	if (v < 0xffffff00) {
	    is64 = false;
	    return v;
	}
	if (v != 0xffffffff)
	    throw new Exception("Bad initial length");
	is64 = true;
	ulong lv;
	lv = parseUInt(p);
	lv |= (cast(ulong) parseUInt(p) << 32);
	return lv;
    }

    ulong parseULEB128(ref char* p)
    {
	ulong v = 0;
	int shift = 0;
	bool done = false;
	char b;

	while (!done) {
	    b = *p++;
	    v |= (b & 0x7f) << shift;
	    shift += 7;
	    if ((b & 0x80) == 0)
		done = true;
	}
	return v;
    }

    long parseSLEB128(ref char* p)
    {
	long v = 0;
	int shift = 0;
	bool done = false;
	char b;

	while (!done) {
	    b = *p++;
	    v |= (b & 0x7f) << shift;
	    shift += 7;
	    if ((b & 0x80) == 0)
		done = true;
	}
	if (shift < 64 && (b & 0x40))
	    v |= -(1 << shift);	// sign extend
	return v;
    }

    Objfile obj_;
    char[] debugSections_[string];
    char[] strtab_;
    NameSet[] pubnames_;
    CompilationUnit[ulong] compilationUnits_;
    FDE[] fdes_;
}

private:

class DwarfLocation: Location
{
    this(CompilationUnit cu, AttributeValue av, size_t len)
    {
	cu_ = cu;
	av_ = av;
	length_ = len;
    }

    override {
	bool valid(MachineState state)
	{
	    if (!state)
		return false;
	    Location loc;
	    if (av_.evalLocation(cu_, state, length_, loc))
		return loc.valid(state);
	    return false;
	}

	size_t length()
	{
	    return length_;
	}

	void length(size_t length)
	{
	    length_ = length;
	}

	ubyte[] readValue(MachineState state)
	{
	    Location loc;
	    if (av_.evalLocation(cu_, state, length_, loc))
		return loc.readValue(state);
	    return null;
	}

	void writeValue(MachineState state, ubyte[] value)
	{
	    Location loc;
	    if (av_.evalLocation(cu_, state, length_, loc))
		return loc.writeValue(state, value);
	}

	bool hasAddress(MachineState state)
	{
	    Location loc;
	    if (av_.evalLocation(cu_, state, length_, loc))
		return loc.hasAddress(state);
	    return false;
	}

	ulong address(MachineState state)
	{
	    Location loc;
	    if (av_.evalLocation(cu_, state, length_, loc))
		return loc.address(state);
	    return 0;
	}

	bool isLval(MachineState state)
	{
	    Location loc;
	    if (av_.evalLocation(cu_, state, length_, loc))
		return loc.isLval(state);
	    return false;
	}

	Location fieldLocation(Location baseLoc, MachineState state)
	{
	    ValueStack stack;
	    if (baseLoc.hasAddress(state)) {
		stack.push(baseLoc.address(state));
		evalExpr(cu_, state, stack);
		return new MemoryLocation(stack.pop, length);
	    } else {
		stack.push(0);
		evalExpr(cu_, state, stack);
		return new SubrangeLocation(baseLoc, stack.pop, length);
	    }
	}

	Location subrange(size_t start, size_t length, MachineState state)
	{
	    Location loc;
	    if (av_.evalLocation(cu_, state, length_, loc))
		return loc.subrange(start, length, state);
	    return null;
	}

	Location dup()
	{
	    return new DwarfLocation(cu_, av_, length_);
	}
    }

    bool evalLocation(MachineState state, out Location loc)
    {
	return av_.evalLocation(cu_, state, length_, loc);
    }

    bool evalExpr(CompilationUnit cu, MachineState state,
		  ref ValueStack stack)
    {
	return av_.evalExpr(cu, state, stack);
    }

    CompilationUnit cu_;
    AttributeValue av_;
    size_t length_;
}

struct ValueStack
{
    size_t length()
    {
	return stack.length;
    }
    void push(long v)
    {
	stack ~= v;
    }
    long pop()
    {
	long v = top();
	stack.length = stack.length - 1;
	return v;
    }
    long top()
    {
	return stack[stack.length - 1];
    }
    long opIndex(int i)
    {
	return stack[stack.length - 1 - i];
    }
    void opIndexAssign(long v, int i)
    {
	stack[stack.length - 1 - i] = v;
    }
    void clear()
    {
	stack.length = 0;
    }
    long[] stack;
}

struct Expr
{
    ulong offset;
    char* start;
    char* end;

    /**
     * Evaluate the expression, leaving the result on the
     * stack. Evaluation stops at the end of the expression or at the
     * first DW_OP_piece or DW_OP_bit_piece. The address of the first
     * unhandled instruction is returned.
     */
    char* evalExpr(CompilationUnit cu, MachineState state, ref ValueStack stack)
    {
	long v, v1;
	int addrlen = cu.addressSize;
	ubyte[] t;
	char* pp;

	/**
	 * Wrap a value based on the target address size.
	 */
	long addrWrap(long v)
	{
	    if (addrlen == 4)
		v &= 0xffffffff;
	    return v;
	}

	char* p = start;
	DwarfFile dw = cu.parent;
	while (p < end) {
	    auto op = *p++;
	    if (op >= DW_OP_lit0 && op <= DW_OP_lit31) {
		stack.push(op - DW_OP_lit0);
		continue;
	    }
	    if (op >= DW_OP_breg0 && op <= DW_OP_breg31) {
		v = cast(long) state.getGR(op - DW_OP_breg0)
		    + dw.parseSLEB128(p);
		stack.push(v);
		continue;
	    }
	    switch (op) {
	    case DW_OP_addr:
		stack.push(offset + dw.parseAddress(p));
		break;

	    case DW_OP_const1u:
		stack.push(dw.parseUByte(p));
		break;

	    case DW_OP_const1s:
		stack.push(dw.parseSByte(p));
		break;

	    case DW_OP_const2u:
		stack.push(dw.parseUShort(p));
		break;

	    case DW_OP_const2s:
		stack.push(dw.parseSShort(p));
		break;

	    case DW_OP_const4u:
		stack.push(dw.parseUInt(p));
		break;

	    case DW_OP_const4s:
		stack.push(dw.parseSInt(p));
		break;

	    case DW_OP_const8u:
		stack.push(dw.parseULong(p));
		break;

	    case DW_OP_const8s:
		stack.push(dw.parseSLong(p));
		break;

	    case DW_OP_constu:
		stack.push(dw.parseULEB128(p));
		break;

	    case DW_OP_consts:
		stack.push(dw.parseSLEB128(p));
		break;

	    case DW_OP_fbreg:
		if (!cu) {
		    stack.push(0);
		    break;
		}
		Location frame;
		v = dw.parseSLEB128(p);
		if (cu.parent.findFrameBase(state, frame))
		    stack.push(frame.address(state) + v);
		else
		    stack.push(v);
		break;

	    case DW_OP_bregx:
		v = cast(long) state.getGR(dw.parseULEB128(p))
		    + dw.parseSLEB128(p);
		stack.push(v);
		break;

	    case DW_OP_dup:
		stack.push(stack.top);
		break;

	    case DW_OP_drop:
		stack.pop;
		break;

	    case DW_OP_pick:
		stack.push(stack[*p++]);
		break;

	    case DW_OP_over:
		stack.push(stack[1]);
		break;

	    case DW_OP_swap:
		v = stack.top;
		stack[0] = stack[1];
		stack[1] = v;
		break;

	    case DW_OP_rot:
		v = stack.top;
		stack[0] = stack[1];
		stack[1] = stack[2];
		stack[2] = v;
		break;

	    case DW_OP_deref:
		v = stack.pop;
		t = state.readMemory(v, addrlen);
		pp = cast(char*) &t[0];
		stack.push(dw.parseAddress(pp));
		break;

	    case DW_OP_deref_size:
		v = stack.pop;
		t = state.readMemory(v, *p++);
		while (t.length < addrlen)
		    t ~= 0;
		pp = cast(char*) &t[0];
		stack.push(dw.parseAddress(pp));
		break;

	    case DW_OP_xderef:
		throw new Exception("DW_OP_xderef not supported");

	    case DW_OP_xderef_size:
		throw new Exception("DW_OP_xderef_size not supported");

	    case DW_OP_push_object_address:
	    case DW_OP_call_frame_cfa:
		throw new Exception("op not supported yet");


	    case DW_OP_abs:
		if (stack.top < 0)
		    stack.push(addrWrap(-stack.pop));
		break;

	    case DW_OP_and:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 & v));
		break;

	    case DW_OP_div:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 / v));
		break;

	    case DW_OP_minus:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 - v));
		break;

	    case DW_OP_mod:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 % v));
		break;

	    case DW_OP_mul:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 * v));
		break;

	    case DW_OP_neg:
		stack.push(addrWrap(-stack.pop));
		break;

	    case DW_OP_not:
		stack.push(addrWrap(~stack.pop));
		break;

	    case DW_OP_or:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 | v));
		break;

	    case DW_OP_plus:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 + v));
		break;

	    case DW_OP_plus_uconst:
		v = stack.pop;
		stack.push(addrWrap(v + dw.parseULEB128(p)));
		break;

	    case DW_OP_shl:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 << v));
		break;

	    case DW_OP_shr:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 >>> v));
		break;

	    case DW_OP_shra:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 >> v));
		break;

	    case DW_OP_xor:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(addrWrap(v1 ^ v));
		break;

	    case DW_OP_le:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(v1 <= v ? 1 : 0);
		break;

	    case DW_OP_ge:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(v1 >= v ? 1 : 0);
		break;

	    case DW_OP_eq:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(v1 == v ? 1 : 0);
		break;

	    case DW_OP_lt:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(v1 < v ? 1 : 0);
		break;

	    case DW_OP_gt:
		v = stack.pop;
		v1 = stack.pop;
		stack.push(v1 > v ? 1 : 0);
		break;

	    case DW_OP_skip:
		v = dw.parseSShort(p);
		p += v;
		break;

	    case DW_OP_bra:
		v = dw.parseSShort(p);
		if (stack.pop != 0)
		    p += v;
		break;

	    case DW_OP_call2:
		v = dw.parseUShort(p);
		if (!cu) {
		    stack.push(0);
		    break;
		}
		auto die = cu.dieMap[v];
		auto loc = die[DW_AT_location];
		if (loc) {
		    pp = loc.b.start;
		    Expr e = Expr(offset, pp, pp + loc.b.length);
		    e.evalExpr(cu, state, stack);
		}
		break;

	    case DW_OP_call4:
		v = dw.parseUInt(p);
		if (!cu) {
		    stack.push(0);
		    break;
		}
		auto die = cu.dieMap[v];
		auto loc = die[DW_AT_location];
		if (loc) {
		    pp = loc.b.start;
		    Expr e = Expr(offset, pp, pp + loc.b.length);
		    e.evalExpr(cu, state, stack);
		}
		break;

	    case DW_OP_call_ref:
		throw new Exception("DW_OP_call_ref mot supported");

	    case DW_OP_nop:
		break;

	    case DW_OP_form_tls_address:
	    case DW_OP_GNU_push_tls_address:
	    case DW_OP_piece:
	    case DW_OP_bit_piece:
		return p-1;

	    default:
		throw new Exception(format("unexpected location opcode %#x",
			op));
	    }
	}
	return p;
    }

    bool evalLocation(CompilationUnit cu, MachineState state,
		      size_t length, out Location result)
    {
	/*
	 * Loop over the expression finding pieces to compose into the
	 * final object.
	 */
	Location loc;
	CompositeLocation cloc;
	char* p = start;
	DwarfFile dw = cu.parent;
	while (p < end) {
	    /*
	     * Check for DW_OP_regN first, otherwise evaluate the
	     * expression to get an address.
	     */
	    auto op = *p;
	    if (op >= DW_OP_reg0 && op <= DW_OP_reg31) {
		p++;
		uint regno = op - DW_OP_reg0;
		loc = new RegisterLocation(regno, length);
	    } else if (op == DW_OP_regx) {
		p++;
		size_t regno = to!size_t(dw.parseULEB128(p));
		loc = new RegisterLocation(regno, length);
	    } else {
		ValueStack stack;
		Expr e = Expr(offset, p, end);
		p = e.evalExpr(cu, state, stack);
		if (p < end
		    && (*p == DW_OP_GNU_push_tls_address
			|| *p == DW_OP_form_tls_address)) {
		    p++;
		    loc = new TLSLocation(cu.parent.obj_.tlsindex,
					  stack.pop - offset, length);
		} else {
		    loc = new MemoryLocation(stack.pop, length);
		}
	    }
	    if (p == end) {
		/*
		 * Simple location
		 */
		result = loc;
		return true;
	    }
	    if (p < end) {
		/*
		 * Composite - add up the pieces
		 */
		if (!cloc) {
		    cloc = new CompositeLocation;
		    result = cloc;
		}
		op = *p++;
		ubyte[] t;
		switch (op) {
		case DW_OP_piece:
		    auto l = dw.parseULEB128(p);
		    loc.length = l;
		    cloc.addPiece(loc, l);
		    break;

		case DW_OP_bit_piece:
		    static if (false) {
			auto nbits = dw.parseULEB128(p);
			auto boff = dw.parseULEB128(p);

			ulong getVal(ubyte[] t)
			{
			    // XXX assume LE for now.
			    ulong v = 0;
			    int shift;
			    foreach (b; t) {
				v |= b << shift;
				shift += 8;
			    }
			    return v;
			}

			size_t len = (nbits + 7) / 8;
			t = loc.readValue(state);
			ulong pv = 0;
			uint i, b;
			for (i = 0, b = 0; len > 0; i++, b += 8, len--)
			    pv |= t[i] << b;

			pv = (pv >>> boff) & ((1 << nbits) - 1);
			// XXX not sure how to compose into obj - need example
			//obj.length = 8; // XXX not correct
			//*cast(long*) obj = pv;
			break;
		    }

		default:
		    throw new Exception("Expected DW_OP_piece or DW_OP_bit_piece");
		}
	    }
	}
	return true;
    }
}

struct Loclist
{
    ulong offset;
    char* start;

    bool evalLocation(CompilationUnit cu, MachineState state,
		      size_t length, out Location result)
    {
	ulong pc = state.pc;
	ulong sOff, eOff, base;

	auto p = start;
	auto lpc = cu.die[DW_AT_low_pc];
	auto dw = cu.parent;
	if (lpc)
	    base = lpc.ul + offset;
	else
	    base = offset;
	for (;;) {
	    sOff = dw.parseAddress(p);
	    eOff = dw.parseAddress(p);
	    if (sOff == 0 && eOff == 0)
		break;
	    if ((cu.is64 && sOff == 0xffffffffffffffff)
		|| (!cu.is64 && sOff == 0xffffffff)) {
		base = eOff;
		continue;
	    }
	    size_t expLen = dw.parseUShort(p);
	    auto expStart = p;
	    auto expEnd = p + expLen;
	    p = expEnd;
	    if (pc >= base + sOff && pc < base + eOff) {
		Expr e = Expr(offset, expStart, expEnd);
		return e.evalLocation(cu, state, length, result);
	    }
	}
	return false;
    }

    bool evalExpr(CompilationUnit cu, MachineState state, ref ValueStack stack)
    {
	ulong pc = state.pc;
	ulong sOff, eOff, base;

	auto p = start;
	base = cu.die[DW_AT_low_pc].ul + offset;
	auto dw = cu.parent;
	for (;;) {
	    sOff = dw.parseAddress(p);
	    eOff = dw.parseAddress(p);
	    if (sOff == 0 && eOff == 0)
		break;
	    if ((cu.is64 && sOff == 0xffffffffffffffff)
		|| (!cu.is64 && sOff == 0xffffffff)) {
		base = eOff;
		continue;
	    }
	    size_t expLen = dw.parseUShort(p);
	    auto expStart = p;
	    auto expEnd = p + expLen;
	    p = expEnd;
	    if (pc >= base + sOff && pc < base + eOff) {
		Expr e = Expr(offset, expStart, expEnd);
		e.evalExpr(cu, state, stack);
		return true;
	    }
	}
	return false;
    }
}

struct NameSet
{
    ulong cuOffset;
    ulong[][string] names;
}

class AttributeValue
{
    this(DwarfFile dw, int f, ref char* p, int addrlen, bool is64,
	 char[] strtab)
    {
	form = f;
    again:
	switch (form) {
	case DW_FORM_ref_addr:
	    if (!is64)
		ul = dw.parseUInt(p);
	    else
		ul = dw.parseULong(p);
	    break;

	case DW_FORM_addr:
	    if (addrlen == 4)
		ul = dw.parseUInt(p);
	    else
		ul = dw.parseULong(p);
	    break;

	case DW_FORM_block:
	    b.length = dw.parseULEB128(p);
	    goto readBlock;

	case DW_FORM_block1:
	    b.length = dw.parseUByte(p);
	    goto readBlock;

	case DW_FORM_block2:
	    b.length = dw.parseUShort(p);
	readBlock:
	    b.start = p;
	    p += b.length;
	    break;

	case DW_FORM_block4:
	    b.length = dw.parseUInt(p);
	    goto readBlock;

	case DW_FORM_ref1:
	case DW_FORM_data1:
	    ul = dw.parseUByte(p);
	    break;

	case DW_FORM_ref2:
	case DW_FORM_data2:
	    ul = dw.parseUShort(p);
	    break;

	case DW_FORM_ref4:
	case DW_FORM_data4:
	    ul = dw.parseUInt(p);
	    break;

	case DW_FORM_ref8:
	case DW_FORM_data8:
	    ul = dw.parseULong(p);
	    break;

	case DW_FORM_string:
	    str = p;
	    while (*p)
		p++;
	    p++;
	    break;

	case DW_FORM_flag:
	    ul = dw.parseUByte(p);
	    break;

	case DW_FORM_sdata:
	    l = dw.parseSLEB128(p);
	    break;

	case DW_FORM_strp:
	    ulong off;
	    if (is64)
		off = dw.parseULong(p);
	    else
		off = dw.parseUInt(p);
	    str = &strtab[off];
	    break;

	case DW_FORM_udata:
	case DW_FORM_ref_udata:
	    ul = dw.parseULEB128(p);
	    break;

	case DW_FORM_indirect:
	    form = to!uint(dw.parseULEB128(p));
	    goto again;

        default:
            assert(0);
	}
    }

    void print()
    {

	switch (form) {
	case DW_FORM_ref_addr:
	case DW_FORM_addr:
	case DW_FORM_ref1:
	case DW_FORM_data1:
	case DW_FORM_ref2:
	case DW_FORM_data2:
	case DW_FORM_ref4:
	case DW_FORM_data4:
	case DW_FORM_ref8:
	case DW_FORM_data8:
	case DW_FORM_flag:
	case DW_FORM_udata:
	case DW_FORM_ref_udata:
	    writefln("%d", ul);
	    break;

	case DW_FORM_block:
	case DW_FORM_block1:
	case DW_FORM_block2:
	case DW_FORM_block4:
	    writefln("block[%d]", b.length);
	    break;

	case DW_FORM_string:
	case DW_FORM_strp:
	    writefln("%s", to!string(str));
	    break;

	case DW_FORM_sdata:
	    writefln("%ld", l);
	    break;

	default:
	    writefln("???");
	}
    }

    bool isBlock()
    {
	return form == DW_FORM_block1 || form == DW_FORM_block2
	    || form == DW_FORM_block4 || form == DW_FORM_block;
    }

    bool isLoclistptr()
    {
	return form == DW_FORM_data4 || form == DW_FORM_data8;
    }

    bool evalLocation(CompilationUnit cu, MachineState state,
		      size_t length, out Location loc)
    {
	if (isLoclistptr) {
	    char[] locs = cu.parent.debugSection(".debug_loc");
	    Loclist ll = Loclist(cu.parent.obj_.offset, &locs[ul]);
	    return ll.evalLocation(cu, state, length, loc);
	} else {
	    assert(isBlock);
	    Expr e = Expr(cu.parent.obj_.offset, b.start, b.end);
	    return e.evalLocation(cu, state, length, loc);
	}
    }

    bool evalExpr(CompilationUnit cu, MachineState state,
		  ref ValueStack stack)
    {
	if (isLoclistptr) {
	    char[] locs = cu.parent.debugSection(".debug_loc");
	    Loclist ll = Loclist(cu.parent.obj_.offset, &locs[ul]);
	    return ll.evalExpr(cu, state, stack);
	} else {
	    assert(isBlock);
	    Expr e = Expr(cu.parent.obj_.offset, b.start, b.end);
	    e.evalExpr(cu, state, stack);
	    return true;
	}
    }

    override string toString()
    {
	return to!string(str);
    }

    uint ui()
    {
	return to!uint(ul);
    }

    int form;
    struct block {
	size_t length;
	char* start;
	char* end()
	{
	    return start + length;
	}
    }

    union {
	ulong ul;
	long l;
	char* str;
	block b;
    }
}

class DIE
{
    CompilationUnit cu_;
    DIE parent_;
    uint tag_;
    AttributeValue attrs_[uint];
    DIE[] children_;
    AddressRange[] addresses_; // set of address ranges for this DIE
    DebugItem debugItem_;

    this(CompilationUnit cu, DIE parent, char* base, ref char* diep,
	 ulong abbrevCode, char*[ulong] abbrevTable,
	 int addrlen, char[] strtab)
    {
	cu_ = cu;
	parent_ = parent;

	auto dw = cu_.parent;
	char* abbrevp = abbrevTable[abbrevCode];
	tag_ = to!uint(dw.parseULEB128(abbrevp));
	auto hasChildren = *abbrevp++ == DW_CHILDREN_yes;

	for (;;) {
	    uint at = to!uint(dw.parseULEB128(abbrevp));
            uint form = to!uint(dw.parseULEB128(abbrevp));
	    if (!at)
		break;
	    AttributeValue val = new AttributeValue(dw, form, diep,
						    addrlen, cu_.is64,
						    strtab);
	    attrs_[at] = val;
	}
	static if (false) {
	    if (tag == DW_TAG_compile_unit) {
		string path;
		if (this[DW_AT_name]) {
		    path = this[DW_AT_name].toString;
		    if (this[DW_AT_comp_dir])
			path = std.path.join(this[DW_AT_comp_dir].toString,
					     path);
		} else {
		    path = "<unknown>";
		}
		writefln("Loading debug information for %s", path);
	    }
	}
	if (hasChildren) {
	    char* p = diep;
	    while ((abbrevCode = dw.parseULEB128(diep)) != 0) {
		DIE die = new DIE(cu, this, base, diep,
				  abbrevCode, abbrevTable,
				  addrlen, strtab);

		cu.dieMap[p - base] = die;
		children_ ~= die;
		p = diep;
	    }
	}
    }

    uint tag()
    {
	return tag_;
    }

    AttributeValue opIndex(int at)
    {
	AttributeValue* p = (at in attrs_);
	if (p) {
	    return *p;
	} else {
	    /*
	     * Check for DW_AT_specification or DW_AT_abstract_origin
	     * and get the field from that if possible.
	     */
	    p = (DW_AT_specification in attrs_);
	    if (p)
		return cu_[*p][at];
	    p = (DW_AT_abstract_origin in attrs_);
	    if (p)
		return cu_[*p][at];
	    return null;
	}
    }

    Type containingType()
    {
	auto ct = this[DW_AT_containing_type];
	if (ct)
	    return cu_[ct].toType;

	/*
	 * GCC doesn't set containing_type - work around it here.
	 */
	if (parent_ && parent_.tag == DW_TAG_structure_type)
	    return parent_.toType;

	auto spec = this[DW_AT_specification];
	if (spec) {
	    DIE die = cu_[spec];
	    return die.containingType;
	}
	return null;
    }

    AddressRange[] addresses()
    {
	if (addresses_.length)
	    return addresses_;

	auto dw = cu_.parent;
	auto offset = dw.obj_.offset;

	if (this[DW_AT_low_pc]
	    && this[DW_AT_high_pc]) {
	    addresses_ ~= AddressRange(this[DW_AT_low_pc].ul + offset,
				       this[DW_AT_high_pc].ul + offset);
	} else if (this[DW_AT_ranges]) {
	    char[] ranges = cu_.parent.debugSection(".debug_ranges");
	    char* p = &ranges[this[DW_AT_ranges].ul];
	    for (;;) {
		ulong start, end;
		start = dw.parseAddress(p);
		end = dw.parseAddress(p);
		if (start == 0 && end == 0)
		    break;
		start += offset;
		end += offset;
		addresses_ ~= AddressRange(start, end);
	    }
	}

	return addresses_;
    }

    bool findInlinedSubroutine(ulong pc, out DIE func)
    {
	if (contains(pc)) {
	    foreach (d; children_)
		if (d.tag == DW_TAG_inlined_subroutine
		    && d.findInlinedSubroutine(pc, func))
		    return true;
	    if (tag == DW_TAG_inlined_subroutine) {
		func = this;
		return true;
	    }
	}
	return false;
    }

    bool findSubprogram(ulong pc, bool findInline, out DIE func)
    {
	if (tag == DW_TAG_subprogram && contains(pc)) {
	    if (findInline) {
		foreach (d; children_)
		    if ((d.tag == DW_TAG_inlined_subroutine
			 || d.tag == DW_TAG_lexical_block)
			&& d.findInlinedSubroutine(pc, func))
			return true;
	    }
	    func = this;
	    return true;
	}
	foreach (d; children_)
	    if (d.findSubprogram(pc, findInline, func))
		return true;
	return false;
    }

    bool contains(ulong pc)
    {
	foreach (a; addresses)
	    if (a.contains(pc))
		return true;
	return false;
    }

    void printIndent(int indent)
    {
	for (int i = 0; i < indent; i++)
	    writef(" ");
    }

    string name()
    {
	auto n = this[DW_AT_name];

	if (n)
	    return n.toString;
	else
	    return "<unknown>";
    }

    DebugItem debugItem()
    {
	if (debugItem_)
	    return debugItem_;

	auto lang = cu_.lang;
	auto offset = cu_.parent.obj_.offset;
	auto t = this[DW_AT_type];
	Type ty = null;
	if (t) {
	    auto d = cu_[t];
	    if (d)
		ty = d.toType;
	}

	Type subType()
	{
	    if (ty)
		return ty;
	    return lang.voidType;
	}

	AttributeValue l;

	switch (tag) {
	case DW_TAG_base_type:
	    auto sz = this[DW_AT_byte_size].ui;
	    if (sz == 0) sz = 1;
	    switch (this[DW_AT_encoding].ul) {
	    case DW_ATE_signed:
		debugItem_ = lang.integerType(name, true, sz);
		break;

	    case DW_ATE_unsigned:
		debugItem_ = lang.integerType(name, false, sz);
		break;

	    case DW_ATE_boolean:
		debugItem_ = lang.booleanType(name, sz);
		break;

	    case DW_ATE_signed_char:
		debugItem_ = lang.charType(name, true, sz);
		break;

	    case DW_ATE_unsigned_char:
		debugItem_ = lang.charType(name, false, sz);
		break;

	    case DW_ATE_float:
		debugItem_ = lang.floatType(name, sz);
		break;

	    case DW_ATE_address:
	    case DW_ATE_complex_float:
	    case DW_ATE_imaginary_float:
	    case DW_ATE_packed_decimal:
	    case DW_ATE_numeric_string:
	    case DW_ATE_edited:
	    case DW_ATE_signed_fixed:
	    case DW_ATE_unsigned_fixed:
	    case DW_ATE_decimal_float:
		writefln("Unsupported base type encoding %d - using integer",
			 this[DW_AT_encoding].ul);
		debugItem_ = lang.integerType(name, false, sz);
		break;

            default:
                assert(0);
	    }
	    break;

	case DW_TAG_pointer_type:
	    debugItem_ = subType.pointerType(cu_.addressSize);
	    break;

	case DW_TAG_const_type:
	    debugItem_ = subType.modifierType("const");
	    break;

	case DW_TAG_packed_type:
	    debugItem_ = subType.modifierType("packed");
	    break;

	case DW_TAG_reference_type:
	    debugItem_ = subType.referenceType(cu_.addressSize);
	    break;

	case DW_TAG_restrict_type:
	    debugItem_ = subType.modifierType("restrict");
	    break;

	case DW_TAG_shared_type:
	    debugItem_ = subType.modifierType("shared");
	    break;

	case DW_TAG_volatile_type:
	    debugItem_ = subType.modifierType("volatile");
	    break;

	case DW_TAG_enumeration_type:
	{
	    uint sz = this[DW_AT_byte_size] ? this[DW_AT_byte_size].ui : 1;
	    auto et = new EnumType(lang, name, sz);
	    foreach (elem; children_) {
		if (elem.tag != DW_TAG_enumerator)
		    continue;
		et.addTag(elem.name, elem[DW_AT_const_value].ul);
	    }
	    debugItem_ = et;
	    break;
	}

	case DW_TAG_structure_type:
	case DW_TAG_class_type:
	case DW_TAG_union_type:
	{
	    uint sz = this[DW_AT_byte_size] ? this[DW_AT_byte_size].ui : 0;
	    string kind;
	    if (tag == DW_TAG_structure_type)
		kind = "struct";
	    else if (tag == DW_TAG_class_type)
		kind = "class";
	    else
		kind = "union";
	    CompoundType ct = new CompoundType(lang, kind, name, sz);

	    /*
	     * Set our memoized type so that we can avoid recursion
	     * when structures reference each other.
	     */
	    debugItem_ = ct;
	    foreach (elem; children_) {
		if (elem.tag == DW_TAG_member)
		    ct.addField(cast(Variable) elem.debugItem);
		else if (elem.tag == DW_TAG_subprogram)
		    ct.addFunction(cast(Function) elem.debugItem);
	    }
	    break;
	}

	case DW_TAG_array_type:
	{
	    ArrayType at = new ArrayType(lang, subType);

	    /*
	     * Set our memoized type so that we can avoid recursion
	     * when structures reference each other.
	     */
	    debugItem_ = at;
	    foreach (elem; children_) {
		if (elem.tag == DW_TAG_subrange_type) {
		    uint lb, ub, count;
		    lb = ub = 0;
		    if (elem[DW_AT_lower_bound])
			lb = elem[DW_AT_lower_bound].ui;
		    if (elem[DW_AT_upper_bound])
			ub = elem[DW_AT_upper_bound].ui;
		    if (elem[DW_AT_count]) {
			lb = 0;
			count = elem[DW_AT_upper_bound].ui;
		    } else {
			count = ub + 1;
		    }
		    at.addDim(lb, count);
		}
	    }
	    break;
	}

	case DW_TAG_darray_type:
	    debugItem_ = new DArrayType(lang, subType,
					this[DW_AT_byte_size].ui);
	    break;

	case DW_TAG_aarray_type:
	    auto keyType = this[DW_AT_containing_type];
	    if (keyType) {
		debugItem_ = new AArrayType(lang, subType,
					    cu_[keyType].toType,
					    this[DW_AT_byte_size].ui);
	    } else {
		writefln("No DW_AT_containing_type attribute for DW_TAG_aarray_type");
		debugItem_ = lang.voidType;
	    }
	    break;

	case DW_TAG_typedef:
	    debugItem_ = new TypedefType(lang, name, subType);
	    break;

	case DW_TAG_formal_parameter:
	case DW_TAG_variable:
	    l = this[DW_AT_location];
	    Location loc;
	    if (l)
		loc = new DwarfLocation(cu_, l, ty.byteWidth);
	    else
		loc = new NoLocation;
	    Value val = new Value(loc, ty);
	    debugItem_ = new Variable(name, val);
	    break;

	case DW_TAG_member:
	    l = this[DW_AT_data_member_location];
	    Location loc;
	    if (ty) {
		if (l)
		    loc = new DwarfLocation(cu_, l, ty.byteWidth);
		else
		    loc = new FirstFieldLocation(ty.byteWidth);
		Value val = new Value(loc, ty);
		debugItem_ = new Variable(name, val);
	    }
	    break;

	case DW_TAG_subroutine_type:
	    auto ft = new FunctionType(lang);
	    if (ty)
		ft.returnType = ty;
	    foreach (d; children_) {
		if (d.tag == DW_TAG_formal_parameter) {
		    if (d[DW_AT_type])
			ft.addArgumentType(cu_[d[DW_AT_type]].toType);
		} else if (d.tag == DW_TAG_unspecified_parameters) {
		    ft.varargs = true;
		}
	    }
	    debugItem_ = ft;
	    break;

	case DW_TAG_subprogram:
	case DW_TAG_inlined_subroutine:
	    Function f = new Function(name, cu_.lang, cu_.addressSize);
	    if (ty)
		f.returnType = ty;
	    f.containingType = this.containingType;
	    f.compilationUnit = cu_;
	    foreach (d; children_) {
		if (d.tag == DW_TAG_formal_parameter)
		    f.addArgument(cast(Variable) d.debugItem);
		else if (d.tag == DW_TAG_unspecified_parameters)
		    f.varargs = true;
		else if (d.tag == DW_TAG_variable)
		    f.addVariable(cast(Variable) d.debugItem);
		else if (d.tag == DW_TAG_lexical_block)
		    f.addScope(cast(LexicalScope) d.debugItem);
	    }
	    ulong addr = 0;
	    if (this[DW_AT_entry_pc])
		addr = this[DW_AT_entry_pc].ul + offset;
	    else if (this[DW_AT_low_pc])
		addr = this[DW_AT_low_pc].ul + offset;
	    f.address = addr;
	    auto inl = this[DW_AT_inline];
	    if (inl)
		if (inl.ul == DW_INL_declared_inlined
		    || inl.ul == DW_INL_declared_not_inlined)
		    f.isInline = true;
	    debugItem_ = f;
	    break;

	case DW_TAG_lexical_block:
	    auto ls = new LexicalScope(cu_.lang, addresses);
	    foreach (d; children_) {
		if (d.tag == DW_TAG_variable)
		    ls.addVariable(cast(Variable) d.debugItem);
		if (d.tag == DW_TAG_lexical_block)
		    ls.addScope(cast(LexicalScope) d.debugItem);
	    }
	    debugItem_ = ls;
	    break;

	default:
	    writefln("Unsupported Dwarf tag %s", tagNames[tag]);
	    debugItem_ = lang.voidType; // XXX not really what is needed
	}
	return debugItem_;
    }

    Type toType()
    {
	return cast(Type) debugItem;
    }

    void print(int indent)
    {
	printIndent(indent);
	writefln("%s", tagNames[tag]);
	foreach (at, val; attrs_) {
	    printIndent(indent + 1);
	    writef("%s = ", attrNames[at]);
	    val.print();
	}
	foreach (kid; children_)
	    kid.print(indent + 2);
    }
}

class CompilationUnit: Scope
{
    this(DwarfFile df)
    {
	parent = df;
    }

    uint addressSize()
    {
	return addressSize_;
    }

    void addressSize(uint v)
    {
	assert(v == 4 || v == 8);
	addressSize_ = v;
    }

    uint segmentSize()
    {
	return segmentSize_;
    }

    void segmentSize(uint v)
    {
	segmentSize_ = v;
    }

    Language lang()
    {
	if (lang_)
	    return lang_;
	auto l = die[DW_AT_language];
	if (!l) {
	    lang_ = CLikeLanguage.instance;
	} else {
	    switch (l.ul) {
	    case DW_LANG_C:
	    case DW_LANG_C89:
	    case DW_LANG_C99:
	    default:
		lang_ = CLikeLanguage.instance;
		break;

	    case DW_LANG_C_plus_plus:
		lang_ = CPlusPlusLanguage.instance;
		break;

	    case DW_LANG_D:
		lang_ = DLanguage.instance;
		break;
	    }
	}
	return lang_;
    }

    string sourceName() {
        loadDIE;
        if (auto name = die[DW_AT_name])
            return name.toString();
        return null;
    }

    string compDir() {
        loadDIE;
        if (auto dir = die[DW_AT_comp_dir])
            return dir.toString();
        return null;
    }

    bool contains(ulong pc)
    {
	if (addresses.length) {
	    foreach (ref a; addresses)
		if (a.contains(pc))
		    return true;
	    return false;
	} else {
	    /*
	     * Load the DIE if necessary and check its attributes
	     */
	    if (die is null)
		loadDIE();
	    addresses = die.addresses;

	    /*
	     * If the CU DIE doesn't have any addresses, try to get
	     * some from the top-level DIEs in the CU.
	     */
	    if (addresses.length == 0) {
		foreach (kid; die.children_)
		    if (kid.contains(pc))
			return true;
		return false;
	    }

	    /*
	     * Now that we have loaded the DIE, try again
	     */
	    return contains(pc);
	}
    }

    void loadDIE()
    {
	if (!die) {
	    char[] info = parent.debugSection(".debug_info");
	    char* p = &info[offset];
	    parent.parseCompilationUnit(this, p);
	    if (!die)
		throw new Exception(
		    "Can't load DIE for compilation unit");
	}
    }

    bool findSubprogram(ulong pc, bool findInline, out DIE func)
    {
	foreach (kid; die.children_)
	    if (kid.findSubprogram(pc, findInline, func))
		return true;
	return false;
    }

    DIE opIndex(AttributeValue av)
    {
	DIE* p = (av.ul in dieMap);
	if (p)
	    return *p;
	else
	    return null;
    }

    override {
	// Scope compliance
	string[] contents(MachineState)
	{
	    string[] res;

	    loadDIE;
	    foreach (d; die.children_) {
		if (d.tag == DW_TAG_variable)
		    res ~= d.name;
	    }
	    return res;
	}
	DebugItem lookup(string name, MachineState)
	{
	    loadDIE;
	    foreach (d; die.children_) {
		if (d.tag == DW_TAG_variable && d.name == name) {
		    return d.debugItem;
		}
	    }
	    return null;
	}
	Type lookupStruct(string name)
	{
	    loadDIE;
	    foreach (d; die.children_) {
		if (d.tag == DW_TAG_structure_type && d.name == name) {
		    return d.toType;
		}
	    }
	    return null;
	}
	Type lookupUnion(string name)
	{
	    loadDIE;
	    foreach (d; die.children_) {
		if (d.tag == DW_TAG_union_type && d.name == name) {
		    return d.toType;
		}
	    }
	    return null;
	}
	Type lookupTypedef(string name)
	{
	    loadDIE;
	    foreach (d; die.children_) {
		if (d.tag == DW_TAG_typedef && d.name == name) {
		    return d.toType;
		}
	    }
	    return null;
	}
    }

    DwarfFile parent;
    ulong offset;		// Offset in .debug_info
    bool is64;			// CU uses 64bit dwarf
    uint addressSize_;		// size in bytes of an address
    uint segmentSize_;		// size in bytes of a segment
    AddressRange[] addresses;	// set of address ranges for this CU
    DIE die;			// top-level DIE for this CU
    DIE[ulong] dieMap;		// map DIE offset to loaded DIE
    Language lang_;
}

class CIE
{
    uint codeAlign;
    int dataAlign;
    uint returnAddress;
    char* instructionStart;
    char* instructionEnd;
}

//debug=unwind;

class FDE
{
    DwarfFile dw;
    CIE cie;
    ulong initialLocation;
    ulong addressRange;
    char* instructionStart;
    char* instructionEnd;

    struct RLoc {
	enum Rule {
	    undefined,
	    sameValue,
	    offsetN,
	    valOffsetN,
	    registerR,
	    expressionE,
	    valExpressionE,
	}
	Rule rule;
	union {
	    long N;
	    uint R;
	    struct block {
		char* start;
		char* end;
	    }
	    block E;
	}
    }
    struct FrameState {
	void clear(FDE fde, uint numRegs)
	{
	    regs.length = numRegs;
	    foreach (rloc; regs) {
		rloc.rule = RLoc.Rule.undefined;
	    }
	    loc = fde.initialLocation;
	}

	RLoc regs[];
	ulong loc;
	uint cfaReg;
	long cfaOffset;
    }

    bool contains(ulong pc)
    {
	return pc >= initialLocation && pc < initialLocation + addressRange;
    }

    Location frameLocation(MachineState state)
    {
	FrameState cieFs, fdeFs;

	cieFs.clear(this, state.grCount);
	fdeFs.clear(this, state.grCount);

	auto pc = state.pc;
	execute(cie.instructionStart, cie.instructionEnd, pc, cieFs, cieFs);

	fdeFs = cieFs;
	execute(instructionStart, instructionEnd, pc, fdeFs, cieFs);

	auto reg = state.getGR(fdeFs.cfaReg);
	return new MemoryLocation(reg + fdeFs.cfaOffset, 1);
    }

    MachineState unwind(MachineState state)
    {
	FrameState cieFs, fdeFs;

	cieFs.clear(this, state.grCount);
	fdeFs.clear(this, state.grCount);

	auto pc = state.pc;
	execute(cie.instructionStart, cie.instructionEnd, pc, cieFs, cieFs);

	fdeFs = cieFs;
	execute(instructionStart, instructionEnd, pc, fdeFs, cieFs);

	if (fdeFs.regs[cie.returnAddress].rule == RLoc.Rule.undefined)
	    return null;
	MachineState newState = state.dup;
	ulong cfa = state.getGR(fdeFs.cfaReg) + fdeFs.cfaOffset;
	foreach (i, rl; fdeFs.regs) {
	    long off;
	    ubyte[] b;
	    switch (rl.rule) {
	    case RLoc.Rule.undefined:
	    case RLoc.Rule.sameValue:
		if (i == state.spregno)
		    newState.setGR(i, cfa);
		break;

	    case RLoc.Rule.offsetN:
		off = rl.N;
		b = state.readMemory(cfa + off, dw.obj_.is64 ? 8 : 4);
		newState.setGR(i, dw.obj_.read(b));
		break;

	    case RLoc.Rule.valOffsetN:
		off = rl.N;
		newState.setGR(i, cfa + off);
		break;

	    case RLoc.Rule.registerR:
		newState.setGR(i, state.getGR(rl.R));
		break;

	    case RLoc.Rule.expressionE:
	    case RLoc.Rule.valExpressionE:
		throw new Exception("no support for frame state stacks");

            default:
                assert(0);
	    }
	}
	return newState;
    }

private:
    void execute(char* p, char* pEnd, ulong pc, ref FrameState fs,
	FrameState cieFs)
    {
	uint reg;
	ulong off;

	while (p < pEnd) {
	    auto op = *p++;
	    switch ((op & 0xc0) ? (op & 0xc0) : op) {
	    case DW_CFA_set_loc:
		fs.loc = dw.parseAddress(p);
		debug(unwind)
		    writefln("DW_CFA_set_loc: 0x%x", fs.loc);
		break;

	    case DW_CFA_advance_loc:
		off = (op & 0x3f) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_advance_loc1:
		off = dw.parseUByte(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc1: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_advance_loc2:
		off = dw.parseUShort(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc2: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_advance_loc4:
		off = dw.parseUInt(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc4: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_MIPS_advance_loc8:
		off = dw.parseULong(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_MIPS_advance_loc8: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_def_cfa:
		fs.cfaReg = to!uint(dw.parseULEB128(p));
		fs.cfaOffset = to!uint(dw.parseULEB128(p));
		debug(unwind)
		    writefln("DW_CFA_def_cfa: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_sf:
		fs.cfaReg = to!uint(dw.parseULEB128(p));
		fs.cfaOffset = to!uint(dw.parseSLEB128(p) * cie.dataAlign);
		debug(unwind)
		    writefln("DW_CFA_def_cfa_sf: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_register:
		fs.cfaReg = to!uint(dw.parseULEB128(p));
		debug(unwind)
		    writefln("DW_CFA_def_cfa_register: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_offset:
		fs.cfaOffset = dw.parseULEB128(p);
		debug(unwind)
		    writefln("DW_CFA_def_cfa_offset: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_offset_sf:
		fs.cfaOffset = dw.parseSLEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_def_cfa_offset_sf: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_expression:
		throw new Exception("no support for CFA expressions");

	    case DW_CFA_undefined:
		reg = to!uint(dw.parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.undefined;
		debug(unwind)
		    writefln("DW_CFA_undefined: reg=%d", reg);
		break;

	    case DW_CFA_same_value:
		reg = to!uint(dw.parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.sameValue;
		debug(unwind)
		    writefln("DW_CFA_same_value: reg=%d", reg);
		break;

	    case DW_CFA_offset:
		reg= op & 0x3f;
		fs.regs[reg].rule = RLoc.Rule.offsetN;
		fs.regs[reg].N = dw.parseULEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_offset: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;

	    case DW_CFA_offset_extended:
		reg = to!uint(dw.parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.offsetN;
		fs.regs[reg].N = dw.parseULEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_offset_extended: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;

	    case DW_CFA_offset_extended_sf:
		reg = to!uint(dw.parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.offsetN;
		fs.regs[reg].N = dw.parseSLEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_offset_extended_sf: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;

	    case DW_CFA_val_offset:
		reg = to!uint(dw.parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.valOffsetN;
		fs.regs[reg].N = dw.parseULEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_val_offset: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;

	    case DW_CFA_register:
		reg = to!uint(dw.parseULEB128(p));
		fs.regs[reg] = fs.regs[dw.parseULEB128(p)];
		debug(unwind)
		    writefln("DW_CFA_register: reg=%d", reg);
		break;

	    case DW_CFA_expression:
		throw new Exception("no support for CFA expressions");

	    case DW_CFA_val_expression:
		throw new Exception("no support for CFA expressions");

	    case DW_CFA_restore:
		reg = op & 0x3f;
		fs.regs[reg] = cieFs.regs[op & 0x3f];
		debug(unwind)
		    writefln("DW_CFA_restore: reg=%d", reg);
		break;

	    case DW_CFA_restore_extended:
		reg = to!uint(dw.parseULEB128(p));
		fs.regs[reg] = cieFs.regs[op & 0x3f];
		debug(unwind)
		    writefln("DW_CFA_restore_extended: reg=%d", reg);
		break;

	    case DW_CFA_remember_state:
	    case DW_CFA_restore_state:
		throw new Exception("no support for frame state stacks");

	    case DW_CFA_GNU_window_save:
		throw new Exception("DW_CFA_GNU_window_save");

	    case DW_CFA_GNU_args_size:
		dw.parseULEB128(p);
		break;

	    case DW_CFA_GNU_negative_offset_extended:
		throw new Exception("DW_CFA_GNU_negative_offset_extended");

	    case DW_CFA_nop:
		break;

	    default:
		throw new Exception(std.string.format(
					"unknown CFA opcode %x", op));
	    }
	    // If we have advanced past the PC, stop
	    if (pc < fs.loc)
		return;
	}
    }
}
