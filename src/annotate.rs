//! Apply VB6 analysis results to a Binary Ninja [`BinaryView`].
//!
//! This module is the bridge between [`crate::analysis::Vb6AnalysisResult`]
//! (pure data) and Binary Ninja's API. It performs the following steps in order:
//!
//! 1. **Type definitions** — Register VB6 struct and enum types in BN's type system.
//! 2. **False function cleanup** — Remove x86 functions BN auto-created in
//!    known VB6 data regions.
//! 3. **Struct overlays** — Apply named struct types at VB6 structure VAs.
//! 4. **Symbol creation** — Define data/function symbols for all VB6 objects.
//! 5. **Import resolution** — Create symbols for resolved `Declare` imports
//!    and register them for LLIL lifting.
//! 6. **Instruction text data** — Register resolved names for disassembly display.
//! 7. **Function creation** — Create P-Code and native functions with correct
//!    platforms and architectures.
//! 8. **MSVBVM60 prototypes** — Apply correct function prototypes to all
//!    MSVBVM60.DLL IAT entries from the export signature database.
//! 9. **Entry point fix** — Mark `ThunRTMain` as noreturn.

use std::collections::HashSet;

use crate::{
    analysis::{CodeEntryKindOwned, Vb6AnalysisResult},
    arch::{self, PCodeFunctionMeta},
    types,
};
use binaryninja::{
    architecture::ArchitectureExt,
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt},
    confidence::{Conf, MAX_CONFIDENCE, MIN_CONFIDENCE},
    platform::Platform,
    rc::Ref,
    symbol::{Symbol, SymbolType},
    types::{FunctionParameter, Type},
};
use visualbasic::vb::exports::{CallingConv, VbParamType};

fn ptr32() -> binaryninja::rc::Ref<Type> {
    Type::pointer_of_width(&Type::void(), 4, false, false, None)
}

/// Apply all VB6 annotations to the [`BinaryView`].
///
/// This is the main entry point called from [`crate::run_vb6_analysis`] after
/// parsing completes. Each step logs progress to the BN console.
pub fn annotate(bv: &BinaryView, result: &Vb6AnalysisResult) {
    arch::clear_all();

    crate::log("Defining VB6 types...");
    types::define_all_types(bv);

    crate::log("Cleaning up false-positive functions in VB6 data regions...");
    cleanup_false_functions(bv, result);

    crate::log("Applying struct overlays...");
    apply_struct_overlays(bv, result);

    crate::log("Creating symbols...");
    create_symbols(bv, result);

    crate::log("Resolving imports...");
    create_import_symbols(bv, result);

    crate::log("Registering instruction text data...");
    register_instruction_text_data(result);

    crate::log("Creating functions...");
    create_functions(bv, result);

    crate::log("Annotating form designer data...");
    annotate_forms(bv, result);

    crate::log("Applying MSVBVM60 import prototypes...");
    apply_msvbvm60_prototypes(bv);

    crate::log("Fixing entry point...");
    fix_entry_point(bv);

    crate::log("VB6 annotation complete.");
}

/// Collect all legitimate code VAs (P-Code, native, stubs) from the analysis.
fn collect_code_vas(result: &Vb6AnalysisResult) -> HashSet<u64> {
    let mut vas = HashSet::new();
    for obj in &result.objects {
        for ce in &obj.code_entries {
            vas.insert(ce.va);
            if let Some(stub_va) = ce.stub_va {
                vas.insert(stub_va);
            }
        }
    }
    vas
}

/// Remove auto-created x86 functions that are false positives in VB6 data.
///
/// We keep functions that are:
/// - In our known code VA set (P-Code stubs, native thunks, event handlers)
/// - The PE entry point or its call target (ThunRTMain)
/// - Import-related (IAT thunks, imported functions)
///
/// Everything else within the VB6-managed .text region is removed.
fn cleanup_false_functions(bv: &BinaryView, result: &Vb6AnalysisResult) {
    let known_code_vas = collect_code_vas(result);

    // Collect VAs we must preserve: entry point + ThunRTMain call target.
    let mut preserve = HashSet::new();
    let entry = bv.entry_point();
    preserve.insert(entry);
    // Read the call target from `push <VbHeader>; call <ThunRTMain>`
    let mut buf = [0u8; 10];
    if bv.read(&mut buf, entry) >= 10 && buf[0] == 0x68 && buf[5] == 0xE8 {
        let rel32 = i32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
        let thunrt = (entry + 10).wrapping_add_signed(rel32 as i64);
        preserve.insert(thunrt);
    }

    let mut removed = 0u32;
    for func in bv.functions().iter() {
        let addr = func.start();
        if known_code_vas.contains(&addr) || preserve.contains(&addr) {
            continue;
        }
        // Keep imported functions (IAT thunks, DLL dispatchers)
        let sym = func.symbol();
        let sym_type = sym.sym_type();
        if matches!(
            sym_type,
            SymbolType::ImportedFunction | SymbolType::ImportAddress
        ) {
            continue;
        }
        bv.remove_auto_function(&func, false);
        removed += 1;
    }
    crate::log(&format!(
        "Removed {} false-positive auto-functions",
        removed
    ));
}

/// Apply named struct types as data variable overlays at known VB6 structure VAs.
///
/// Skips any VA that overlaps a known code entry to avoid corrupting functions.
fn apply_struct_overlays(bv: &BinaryView, result: &Vb6AnalysisResult) {
    let code_vas = collect_code_vas(result);
    let safe = |va: u64| -> bool { va != 0 && !code_vas.contains(&va) };

    if safe(result.vb_header_va) {
        apply_type_at(bv, result.vb_header_va, "VB6_VbHeader");
    }
    if safe(result.project_data_va) {
        apply_type_at(bv, result.project_data_va, "VB6_ProjectData");
    }
    if safe(result.object_table_va) {
        apply_type_at(bv, result.object_table_va, "VB6_ObjectTable");
    }
    if let Some(va) = result.project_info2_va {
        if safe(va) {
            apply_type_at(bv, va, "VB6_ProjectInfo2");
        }
    }
    if safe(result.com_register_data_va) {
        apply_type_at(bv, result.com_register_data_va, "VB6_ComRegData");
    }
    for &va in &result.com_reg_object_vas {
        if safe(va) {
            apply_type_at(bv, va, "VB6_ComRegObject");
        }
    }
    // Type COM registration interface GUID arrays as GUID[N]
    let guid_ty = Type::array(&Type::int(1, false), 16);
    for (va, count, label) in &result.com_reg_guid_arrays {
        if *va != 0 && safe(*va) {
            let arr_ty = Type::array(&guid_ty, *count as u64);
            bv.define_auto_data_var(*va, &arr_ty);
            define_symbol(bv, SymbolType::Data, *va, label);
        }
    }
    // Type inline ANSI strings as char[] with descriptive symbols
    for (va, label, s) in &result.data_strings {
        if *va != 0 && safe(*va) {
            let str_ty = Type::array(&Type::char(), s.len() as u64 + 1);
            bv.define_auto_data_var(*va, &str_ty);
            define_symbol(bv, SymbolType::Data, *va, label);
        }
    }
    for &va in &result.gui_entry_vas {
        if safe(va) {
            apply_type_at(bv, va, "VB6_GuiTableEntry");
        }
    }
    for ext in &result.external_entry_info {
        if safe(ext.info_va) {
            let type_name = if ext.is_declare {
                "VB6_ExternalDeclareInfo"
            } else {
                "VB6_ExternalTypelibInfo"
            };
            apply_type_at(bv, ext.info_va, type_name);
        }
    }

    for obj in &result.objects {
        if safe(obj.descriptor_va) {
            apply_type_at(bv, obj.descriptor_va, "VB6_PublicObjectDescriptor");
        }
        if safe(obj.object_info_va) {
            apply_type_at(bv, obj.object_info_va, "VB6_ObjectInfo");
        }
        if let Some(va) = obj.optional_info_va {
            if safe(va) {
                apply_type_at(bv, va, "VB6_OptionalObjectInfo");
            }
        }
        if let Some(va) = obj.private_object_va {
            if safe(va) {
                apply_type_at(bv, va, "VB6_PrivateObjectDescriptor");
            }
        }
        for ce in &obj.code_entries {
            if ce.kind == CodeEntryKindOwned::PCode {
                if let Some(pcode_size) = ce.pcode_size {
                    let proc_dsc_va = ce.va + pcode_size as u64;
                    if safe(proc_dsc_va) {
                        apply_type_at(bv, proc_dsc_va, "VB6_ProcDscInfo");
                        type_cleanup_tables(bv, proc_dsc_va);
                    }
                }
            }
        }
        for ctrl in &obj.controls {
            if safe(ctrl.control_info_va) {
                apply_type_at(bv, ctrl.control_info_va, "VB6_ControlInfo");
            }
        }
        for &va in &obj.func_type_desc_vas {
            if safe(va) {
                apply_type_at(bv, va, "VB6_FuncTypDesc");
            }
        }
        // Define method dispatch tables as u32[] arrays
        if obj.methods_table_va != 0 && obj.method_count > 0 && safe(obj.methods_table_va) {
            let arr_ty = Type::array(&Type::int(4, false), obj.method_count as u64);
            bv.define_auto_data_var(obj.methods_table_va, &arr_ty);
            define_symbol(
                bv,
                SymbolType::Data,
                obj.methods_table_va,
                &format!("vb6::methods::{}", obj.name),
            );
        }

        // Define constants pool as void*[] array
        if obj.constants_va != 0 && obj.constants_count > 0 && safe(obj.constants_va) {
            let arr_ty = Type::array(&ptr32(), obj.constants_count as u64);
            bv.define_auto_data_var(obj.constants_va, &arr_ty);
            define_symbol(
                bv,
                SymbolType::Data,
                obj.constants_va,
                &format!("vb6::constants::{}", obj.name),
            );
        }

        // Define FuncTypDesc pointer table as void*[] array
        if obj.func_type_descs_table_va != 0
            && obj.func_type_desc_table_count > 0
            && safe(obj.func_type_descs_table_va)
        {
            let arr_ty = Type::array(&ptr32(), obj.func_type_desc_table_count as u64);
            bv.define_auto_data_var(obj.func_type_descs_table_va, &arr_ty);
            define_symbol(
                bv,
                SymbolType::Data,
                obj.func_type_descs_table_va,
                &format!("vb6::ftd_table::{}", obj.name),
            );
        }

        // Define GUID data from OptionalObjectInfo
        if let Some(ref opt) = obj.optional_info_data {
            let guid_ty = Type::array(&Type::int(1, false), 16);

            if opt.object_clsid_va != 0 && safe(opt.object_clsid_va) {
                bv.define_auto_data_var(opt.object_clsid_va, &guid_ty);
                define_symbol(
                    bv,
                    SymbolType::Data,
                    opt.object_clsid_va,
                    &format!("vb6::clsid::{}", obj.name),
                );
            }

            if opt.gui_guid_table_va != 0 && opt.gui_guids_count > 0 && safe(opt.gui_guid_table_va)
            {
                let arr_ty = Type::array(&guid_ty, opt.gui_guids_count as u64);
                bv.define_auto_data_var(opt.gui_guid_table_va, &arr_ty);
                define_symbol(
                    bv,
                    SymbolType::Data,
                    opt.gui_guid_table_va,
                    &format!("vb6::gui_guids::{}", obj.name),
                );
            }

            if opt.default_iid_table_va != 0
                && opt.default_iid_count > 0
                && safe(opt.default_iid_table_va)
            {
                let arr_ty = Type::array(&guid_ty, opt.default_iid_count as u64);
                bv.define_auto_data_var(opt.default_iid_table_va, &arr_ty);
                define_symbol(
                    bv,
                    SymbolType::Data,
                    opt.default_iid_table_va,
                    &format!("vb6::default_iids::{}", obj.name),
                );
            }

            if opt.events_iid_table_va != 0
                && opt.events_iid_count > 0
                && safe(opt.events_iid_table_va)
            {
                let arr_ty = Type::array(&guid_ty, opt.events_iid_count as u64);
                bv.define_auto_data_var(opt.events_iid_table_va, &arr_ty);
                define_symbol(
                    bv,
                    SymbolType::Data,
                    opt.events_iid_table_va,
                    &format!("vb6::event_iids::{}", obj.name),
                );
            }

            if opt.method_link_table_va != 0
                && opt.method_link_count > 0
                && safe(opt.method_link_table_va)
            {
                let arr_ty = Type::array(&ptr32(), opt.method_link_count as u64);
                bv.define_auto_data_var(opt.method_link_table_va, &arr_ty);
                define_symbol(
                    bv,
                    SymbolType::Data,
                    opt.method_link_table_va,
                    &format!("vb6::method_links::{}", obj.name),
                );
            }
        }

        // Define event sink vtables and GUIDs for controls.
        // The vtable has a 6-pointer header (0x18 bytes: null, ControlInfo
        // back-ptr, ObjectInfo back-ptr, QueryInterface, AddRef, Release)
        // followed by event_handler_slots handler VA entries.
        for ctrl in &obj.controls {
            if ctrl.event_sink_vtable_va != 0 && safe(ctrl.event_sink_vtable_va) {
                let total_entries = 6 + ctrl.event_handler_slots as u64;
                let arr_ty = Type::array(&ptr32(), total_entries);
                bv.define_auto_data_var(ctrl.event_sink_vtable_va, &arr_ty);
                define_symbol(
                    bv,
                    SymbolType::Data,
                    ctrl.event_sink_vtable_va,
                    &format!("vb6::evt_vtbl::{}.{}", obj.name, ctrl.name),
                );

                // Rich comment on the vtable showing event slot→name mapping
                let mut comment_lines = vec![format!(
                    "Event sink vtable: {}.{} ({} slots)",
                    obj.name, ctrl.name, ctrl.event_handler_slots
                )];
                comment_lines.push("+0x00 reserved".to_string());
                comment_lines.push("+0x04 ControlInfo backptr".to_string());
                comment_lines.push("+0x08 ObjectInfo backptr".to_string());
                comment_lines.push("+0x0C QueryInterface thunk".to_string());
                comment_lines.push("+0x10 AddRef thunk".to_string());
                comment_lines.push("+0x14 Release thunk".to_string());
                for &(slot, ref event_name) in &ctrl.event_slot_names {
                    let offset = 0x18 + slot as u32 * 4;
                    comment_lines.push(format!(
                        "+0x{offset:02X} [{slot:2}] {}.{event_name}",
                        ctrl.name
                    ));
                }
                bv.set_comment_at(ctrl.event_sink_vtable_va, &comment_lines.join("\n"));

                // Name IUnknown thunk stubs
                let (qi, ar, rel) = ctrl.iunknown_thunk_vas;
                if qi != 0 {
                    define_symbol(
                        bv,
                        SymbolType::Function,
                        qi,
                        &format!("EVENT_SINK_QueryInterface::{}", obj.name),
                    );
                }
                if ar != 0 {
                    define_symbol(
                        bv,
                        SymbolType::Function,
                        ar,
                        &format!("EVENT_SINK_AddRef::{}", obj.name),
                    );
                }
                if rel != 0 {
                    define_symbol(
                        bv,
                        SymbolType::Function,
                        rel,
                        &format!("EVENT_SINK_Release::{}", obj.name),
                    );
                }
            }

            if ctrl.guid_va != 0 && safe(ctrl.guid_va) {
                let guid_ty = Type::array(&Type::int(1, false), 16);
                bv.define_auto_data_var(ctrl.guid_va, &guid_ty);
                define_symbol(
                    bv,
                    SymbolType::Data,
                    ctrl.guid_va,
                    &format!("vb6::guid::{}.{}", obj.name, ctrl.name),
                );
            }
        }

        // Define method names table as void*[method_count]
        if obj.method_names_va != 0 && obj.method_count > 0 && safe(obj.method_names_va) {
            let arr_ty = Type::array(&ptr32(), obj.method_count as u64);
            bv.define_auto_data_var(obj.method_names_va, &arr_ty);
            define_symbol(
                bv,
                SymbolType::Data,
                obj.method_names_va,
                &format!("vb6::method_names::{}", obj.name),
            );
        }

        // Define object name string as char[]
        if obj.object_name_va != 0 && safe(obj.object_name_va) {
            let name_len = obj.name.len() as u64 + 1; // include null terminator
            let str_ty = Type::array(&Type::char(), name_len);
            bv.define_auto_data_var(obj.object_name_va, &str_ty);
            define_symbol(
                bv,
                SymbolType::Data,
                obj.object_name_va,
                &format!("vb6::name::{}", obj.name),
            );
        }

        // Define BSTR string data from constants pool entries.
        // Each BSTR has a 4-byte length prefix at va-4 and UTF-16LE data at va.
        let wchar_ty = Type::int(2, false);
        for &(bstr_va, byte_len) in &obj.const_pool_bstrs {
            if bstr_va == 0 || !safe(bstr_va) {
                continue;
            }
            let char_count = byte_len as u64 / 2;
            if char_count == 0 {
                continue;
            }
            // Type the length prefix at va-4 as uint32_t
            let len_va = bstr_va - 4;
            if safe(len_va) {
                bv.define_auto_data_var(len_va, &Type::int(4, false));
                define_symbol(
                    bv,
                    SymbolType::Data,
                    len_va,
                    &format!("vb6::bstr_len::{}_{:08x}", obj.name, bstr_va),
                );
            }
            // Type the string data as wchar16[N]
            let str_ty = Type::array(&wchar_ty, char_count + 1); // +1 for null terminator
            bv.define_auto_data_var(bstr_va, &str_ty);
            define_symbol(
                bv,
                SymbolType::Data,
                bstr_va,
                &format!("vb6::bstr::{}_{:08x}", obj.name, bstr_va),
            );
        }

        // Define individual GUID data (16 bytes each) from GUID pointer tables
        let guid_ty = Type::array(&Type::int(1, false), 16);
        for &guid_va in &obj.guid_data_vas {
            if guid_va != 0 && safe(guid_va) {
                bv.define_auto_data_var(guid_va, &guid_ty);
            }
        }
    }
}

/// Define a named struct type as an auto data variable at `va`.
fn apply_type_at(bv: &BinaryView, va: u64, type_name: &str) {
    if let Some(ty) = bv.type_by_name(type_name) {
        bv.define_auto_data_var(va, &*ty);
    }
}

/// Type both cleanup tables after a ProcDscInfo header.
///
/// Reads `wTotalSize` at +0x0A to find the primary table extent, then
/// reads the secondary table's self-size at that offset. Each table gets
/// a `VB6_CleanupTableHeader` struct overlay plus entry data typing.
fn type_cleanup_tables(bv: &BinaryView, proc_dsc_va: u64) {
    let mut buf = [0u8; 4];

    // Read wTotalSize at +0x0A → offset to secondary table
    if bv.read(&mut buf[..2], proc_dsc_va + 0x0A) < 2 {
        return;
    }
    let total_size = u16::from_le_bytes([buf[0], buf[1]]) as u64;
    if total_size < 0x18 {
        return;
    }

    // Primary table header at proc_dsc_va + 0x18
    // (fields 0x18-0x23 are already in VB6_ProcDscInfo struct, so we only
    // need to type the entries that follow at +0x24)
    if bv.read(&mut buf[..2], proc_dsc_va + 0x18) >= 2 {
        let table1_size = u16::from_le_bytes([buf[0], buf[1]]) as u64;
        let entry_bytes = table1_size.saturating_sub(0x0C);
        if entry_bytes > 0 {
            let entries_va = proc_dsc_va + 0x24;
            let arr_ty = Type::array(&Type::int(1, false), entry_bytes);
            bv.define_auto_data_var(entries_va, &arr_ty);
        }
    }

    // Secondary table at proc_dsc_va + total_size
    let table2_va = proc_dsc_va + total_size;
    if bv.read(&mut buf[..2], table2_va) >= 2 {
        let table2_size = u16::from_le_bytes([buf[0], buf[1]]) as u64;
        if table2_size >= 0x0C {
            apply_type_at(bv, table2_va, "VB6_CleanupTableHeader");
            let entry_bytes = table2_size.saturating_sub(0x0C);
            if entry_bytes > 0 {
                let entries_va = table2_va + 0x0C;
                let arr_ty = Type::array(&Type::int(1, false), entry_bytes);
                bv.define_auto_data_var(entries_va, &arr_ty);
            }
        }
    }
}

/// Create named data symbols for all VB6 structures, ProcDscInfo headers,
/// and control info blocks.
fn create_symbols(bv: &BinaryView, result: &Vb6AnalysisResult) {
    define_symbol(bv, SymbolType::Data, result.vb_header_va, "vb6::VbHeader");
    define_symbol(
        bv,
        SymbolType::Data,
        result.project_data_va,
        "vb6::ProjectData",
    );
    define_symbol(
        bv,
        SymbolType::Data,
        result.object_table_va,
        "vb6::ObjectTable",
    );

    if let Some(va) = result.project_info2_va {
        define_symbol(bv, SymbolType::Data, va, "vb6::ProjectInfo2");
    }
    if result.com_register_data_va != 0 {
        define_symbol(
            bv,
            SymbolType::Data,
            result.com_register_data_va,
            "vb6::ComRegData",
        );
    }
    if result.gui_table_va != 0 {
        define_symbol(bv, SymbolType::Data, result.gui_table_va, "vb6::GuiTable");
    }

    for obj in &result.objects {
        define_symbol(
            bv,
            SymbolType::Data,
            obj.descriptor_va,
            &format!("vb6::obj::{}", obj.name),
        );
        define_symbol(
            bv,
            SymbolType::Data,
            obj.object_info_va,
            &format!("vb6::info::{}", obj.name),
        );

        if let Some(va) = obj.optional_info_va {
            define_symbol(
                bv,
                SymbolType::Data,
                va,
                &format!("vb6::optinfo::{}", obj.name),
            );
        }
        if let Some(va) = obj.private_object_va {
            define_symbol(
                bv,
                SymbolType::Data,
                va,
                &format!("vb6::private::{}", obj.name),
            );
        }

        for ce in &obj.code_entries {
            if ce.kind == CodeEntryKindOwned::PCode {
                if let Some(pcode_size) = ce.pcode_size {
                    let proc_dsc_va = ce.va + pcode_size as u64;
                    let name = ce.name.as_deref().unwrap_or("?");
                    define_symbol(
                        bv,
                        SymbolType::Data,
                        proc_dsc_va,
                        &format!("vb6::proc::{}.{}", obj.name, name),
                    );
                }
            }
        }

        for ctrl in &obj.controls {
            define_symbol(
                bv,
                SymbolType::Data,
                ctrl.control_info_va,
                &format!("vb6::ctrl::{}.{}", obj.name, ctrl.name),
            );
        }
    }
}

/// Create named symbols for resolved VB6 `Declare` imports and COM typelib
/// references, and register their VAs with [`crate::arch`] so the LLIL lifter
/// can resolve `ImpAdCall` targets.
fn create_import_symbols(bv: &BinaryView, result: &Vb6AnalysisResult) {
    let ext_entry_size = 8u64;
    let mut count = 0u32;
    for (i, imp) in result.resolved_imports.iter().enumerate() {
        if let Some(imp) = imp {
            let entry_va = result.proj_ext_table_va + (i as u64) * ext_entry_size;
            if entry_va == 0 {
                continue;
            }
            let name = format!("{}!{}", imp.library, imp.function);
            define_symbol(bv, SymbolType::Data, entry_va, &name);
            arch::register_import_target(i as u16, entry_va);
            count += 1;
        }
    }
    if count > 0 {
        crate::log(&format!(
            "Resolved {} imports from {} external table entries",
            count,
            result.resolved_imports.len()
        ));
    }
}

/// Register pre-resolved data into [`crate::arch`] global maps for
/// `instruction_text` operand display.
fn register_instruction_text_data(result: &Vb6AnalysisResult) {
    for (i, name) in result.resolved_import_names.iter().enumerate() {
        if let Some(name) = name {
            arch::register_import_name(i as u16, name.clone());
        }
    }

    for &(data_const_va, offset, ref s) in &result.resolved_const_strings {
        arch::register_const_string(data_const_va, offset, s.clone());
    }

    for obj in &result.objects {
        for (c_idx, ctrl) in obj.controls.iter().enumerate() {
            arch::register_control_name(obj.object_index, c_idx as u16, ctrl.name.clone());
        }
    }
}

/// Create BN functions for all code entries with the correct platform.
///
/// P-Code entries use the `vb6-pcode` platform and custom architecture.
/// Existing x86 functions at P-Code addresses are removed first, since BN's
/// initial analysis may have created them. Native, thunk, and event handler
/// entries use the default x86 platform.
fn create_functions(bv: &BinaryView, result: &Vb6AnalysisResult) {
    let pcode_platform = Platform::by_name("vb6-pcode");
    match &pcode_platform {
        Some(p) => crate::log(&format!("Found P-Code platform: '{}'", p.name())),
        None => crate::log_warn("Could not find 'vb6-pcode' platform"),
    }

    for obj in &result.objects {
        for ce in &obj.code_entries {
            if ce.va == 0 {
                continue;
            }

            let full_name = match &ce.name {
                Some(n) => format!("{}.{}", obj.name, n),
                None => format!("{}.sub_{:08x}", obj.name, ce.va),
            };

            match ce.kind {
                CodeEntryKindOwned::PCode => {
                    let pcode_size = ce.pcode_size.unwrap_or(0);
                    let data_const_va = ce.data_const_va.unwrap_or(0);
                    let proc_dsc_va = ce.va + pcode_size as u64;
                    arch::register_pcode_function(
                        ce.va,
                        PCodeFunctionMeta {
                            pcode_size,
                            data_const_va,
                            object_index: ce.object_index,
                        },
                    );

                    if let Some(platform) = pcode_platform.as_deref() {
                        for existing in bv.functions_at(ce.va).iter() {
                            bv.remove_user_function(&existing);
                        }
                        let func = bv.add_user_function_with_platform(ce.va, platform);
                        match &func {
                            Some(f) => crate::log(&format!(
                                "Created P-Code func '{}' at 0x{:08x}, arch={}, platform={}",
                                full_name,
                                ce.va,
                                f.arch().name(),
                                f.platform().name()
                            )),
                            None => crate::log_warn(&format!(
                                "Failed to create P-Code func '{}' at 0x{:08x}",
                                full_name, ce.va
                            )),
                        }
                    }
                    define_symbol(bv, SymbolType::Function, ce.va, &full_name);

                    if let Some(stub_va) = ce.stub_va {
                        if stub_va != 0 && stub_va != proc_dsc_va && stub_va != ce.va {
                            if let Some(platform) = bv.default_platform() {
                                bv.add_user_function_with_platform(stub_va, &platform);
                            }
                            define_symbol(
                                bv,
                                SymbolType::Function,
                                stub_va,
                                &format!("{full_name}_stub"),
                            );
                        }
                    }
                }
                CodeEntryKindOwned::Native => {
                    if let Some(platform) = bv.default_platform() {
                        bv.add_user_function_with_platform(ce.va, &platform);
                    }
                    define_symbol(bv, SymbolType::Function, ce.va, &full_name);
                }
                CodeEntryKindOwned::NativeThunk => {
                    if let Some(platform) = bv.default_platform() {
                        bv.add_user_function_with_platform(ce.va, &platform);
                    }
                    define_symbol(
                        bv,
                        SymbolType::Function,
                        ce.va,
                        &format!("{full_name}_thunk"),
                    );
                }
                CodeEntryKindOwned::EventHandler => {
                    if let Some(platform) = bv.default_platform() {
                        bv.add_user_function_with_platform(ce.va, &platform);
                    }
                    define_symbol(bv, SymbolType::Function, ce.va, &full_name);
                }
            }
        }
    }
}

/// Mark `ThunRTMain` as noreturn to prevent BN from disassembling VB6 data
/// structures as x86 code after the entry point `call` instruction.
/// Annotate form designer data: struct overlays, control/resource symbols, rich comments.
fn annotate_forms(bv: &BinaryView, result: &Vb6AnalysisResult) {
    let code_vas = collect_code_vas(result);
    let safe = |va: u64| -> bool { va != 0 && !code_vas.contains(&va) };

    for form in &result.forms {
        if form.form_data_va == 0 {
            continue;
        }

        // Apply FormDataHeader struct overlay
        if safe(form.form_data_va) {
            apply_type_at(bv, form.form_data_va, "VB6_FormDataHeader");
            define_symbol(
                bv,
                SymbolType::Data,
                form.form_data_va,
                &format!("vb6::form::{}", form.object_name),
            );
        }

        // Type control record blobs
        for ctrl in &form.controls {
            if ctrl.record_offset > 0 {
                let va = form.form_data_va + ctrl.record_offset as u64;
                if safe(va) {
                    let ty = Type::array(&Type::int(1, false), ctrl.record_size as u64);
                    bv.define_auto_data_var(va, &ty);
                    define_symbol(
                        bv,
                        SymbolType::Data,
                        va,
                        &format!("vb6::form::{}.{}", form.object_name, ctrl.name),
                    );
                }
            }
        }

        // Type embedded resource blobs
        for res in &form.resources {
            let va = form.form_data_va + res.offset_in_form as u64;
            if safe(va) {
                let total = res.size + 4; // +4 for size prefix
                let ty = Type::array(&Type::int(1, false), total as u64);
                bv.define_auto_data_var(va, &ty);
                let kind = if res.is_bmp { "BMP" } else { "resource" };
                define_symbol(
                    bv,
                    SymbolType::Data,
                    va,
                    &format!(
                        "vb6::{}::{}.{}.{}",
                        kind, form.object_name, res.control_name, res.property_name
                    ),
                );
            }
        }

        // Build rich comment
        let comment = build_form_comment(form);
        if !comment.is_empty() {
            bv.set_comment_at(form.form_data_va, &comment);
        }
    }

    if !result.forms.is_empty() {
        let res_count: usize = result.forms.iter().map(|f| f.resources.len()).sum();
        crate::log(&format!(
            "Annotated {} forms, {} embedded resources",
            result.forms.len(),
            res_count,
        ));
    }
}

/// Build a rich multi-line comment summarizing form hierarchy, properties, and handlers.
fn build_form_comment(form: &crate::analysis::FormAnalysis) -> String {
    let mut lines = Vec::new();

    lines.push(format!(
        "Form: {} ({}x{} twips)",
        form.object_name, form.width, form.height
    ));

    // Form-level properties
    for p in &form.form_properties {
        lines.push(format!("  {}: {}", p.name, p.value));
    }

    // Controls with hierarchy indentation
    for ctrl in &form.controls {
        let indent = "  ".repeat(ctrl.depth as usize + 1);
        lines.push(String::new()); // blank line between controls
        lines.push(format!("{}{} ({})", indent, ctrl.name, ctrl.control_type));

        for p in &ctrl.properties {
            lines.push(format!("{}  {}: {}", indent, p.name, p.value));
        }

        for (handler_name, handler_va) in &ctrl.event_handlers {
            lines.push(format!(
                "{}  -> {} [0x{:08x}]",
                indent, handler_name, handler_va
            ));
        }
    }

    // Embedded resources summary
    let resources: Vec<_> = form.resources.iter().filter(|r| r.size > 0).collect();
    if !resources.is_empty() {
        lines.push(String::new());
        lines.push("--- Embedded Resources ---".to_string());
        for res in resources {
            let kind = if res.is_bmp { "BMP" } else { "binary" };
            lines.push(format!(
                "  {}.{}: {} ({}B) *** EMBEDDED RESOURCE ***",
                res.control_name, res.property_name, kind, res.size
            ));
        }
    }

    lines.join("\n")
}

fn fix_entry_point(bv: &BinaryView) {
    let entry = bv.entry_point();
    if entry == 0 {
        return;
    }

    let mut buf = [0u8; 10];
    if bv.read(&mut buf, entry) < 10 {
        return;
    }
    if buf[0] != 0x68 || buf[5] != 0xE8 {
        return;
    }

    let rel32 = i32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
    let call_target = (entry + 10).wrapping_add_signed(rel32 as i64);

    for func in bv.functions_at(call_target).iter() {
        func.set_can_return_user(false);
        crate::log(&format!(
            "Marked ThunRTMain at 0x{:08x} as noreturn",
            call_target
        ));
    }
}

/// Apply correct function prototypes to all MSVBVM60.DLL IAT entries.
///
/// Iterates all functions with `ImportedFunction` or `ImportAddress` symbol
/// types, looks up their name in the MSVBVM60 export signature database,
/// and applies the correct calling convention, return type, and parameter
/// types via [`binaryninja::function::Function::set_auto_type`].
fn apply_msvbvm60_prototypes(bv: &BinaryView) {
    let arch = match bv.default_arch() {
        Some(a) => a,
        None => return,
    };

    let cc_stdcall = arch.get_stdcall_calling_convention();
    let cc_cdecl = arch.get_cdecl_calling_convention();
    let cc_fastcall = arch
        .get_fastcall_calling_convention()
        .or_else(|| arch.calling_convention_by_name("fastcall"));

    if cc_fastcall.is_none() {
        crate::log_warn(
            "No fastcall calling convention available — fastcall imports will be skipped",
        );
    }

    let mut applied = 0u32;
    for func in bv.functions().iter() {
        let sym = func.symbol();
        let sym_type = sym.sym_type();
        if !matches!(
            sym_type,
            SymbolType::ImportedFunction | SymbolType::ImportAddress
        ) {
            continue;
        }

        let name = sym.short_name().to_string_lossy().into_owned();

        // Try name lookup first, then ordinal lookup for "Ordinal_MSVBVM60_NNN"
        let sig = if let Some(s) = visualbasic::vb::exports::lookup_export(&name) {
            Some(s)
        } else if let Some(ordinal) = parse_msvbvm60_ordinal(&name) {
            visualbasic::vb::exports::lookup_export_by_ordinal(ordinal)
        } else {
            None
        };

        let sig = match sig {
            Some(s) => s,
            None => continue,
        };

        // Skip special calling conventions (x87 intrinsics, FDIV workarounds)
        if sig.calling_convention == CallingConv::Special {
            continue;
        }

        let cc = match sig.calling_convention {
            CallingConv::Stdcall => cc_stdcall.as_deref(),
            CallingConv::Cdecl => cc_cdecl.as_deref(),
            CallingConv::Fastcall => cc_fastcall.as_deref(),
            CallingConv::Special => None,
        };

        let cc = match cc {
            Some(c) => c,
            None => continue,
        };

        // Build return type
        let ret_ty = vbtype_to_bn(sig.return_type, bv);

        // Build parameter list
        let params: Vec<FunctionParameter> = sig
            .params
            .iter()
            .map(|p| {
                FunctionParameter::new(
                    Conf::new(vbtype_to_bn(p.ty, bv), MAX_CONFIDENCE),
                    p.name.to_string(),
                    None,
                )
            })
            .collect();

        let func_ty = Type::function_with_opts(
            &*ret_ty,
            &params,
            sig.variadic,
            Conf::new(cc.to_owned(), MAX_CONFIDENCE),
            Conf::new(0i64, MIN_CONFIDENCE),
        );

        func.set_user_type(&func_ty);

        // For ordinal-only exports with a discovered real name, also rename
        if sig.ordinal > 0 && !name.starts_with("__vba") && name.starts_with("Ordinal_") {
            define_symbol(bv, SymbolType::ImportedFunction, func.start(), sig.name);
        }

        applied += 1;
    }

    if applied > 0 {
        crate::log(&format!("Applied {} MSVBVM60 import prototypes", applied));
    }
}

/// Parse `"Ordinal_MSVBVM60_NNN"` into `Some(NNN)`.
fn parse_msvbvm60_ordinal(name: &str) -> Option<u16> {
    name.strip_prefix("Ordinal_MSVBVM60_")?.parse().ok()
}

/// Convert a [`VbParamType`] to a Binary Ninja [`Type`].
fn vbtype_to_bn(ty: VbParamType, bv: &BinaryView) -> Ref<Type> {
    match ty {
        VbParamType::Void => Type::void(),
        VbParamType::Int16 => Type::int(2, true),
        VbParamType::UInt16 => Type::int(2, false),
        VbParamType::Int32 => Type::int(4, true),
        VbParamType::UInt32 => Type::int(4, false),
        VbParamType::Int64 => Type::int(8, true),
        VbParamType::UInt8 => Type::int(1, false),
        VbParamType::Float => Type::float(4),
        VbParamType::Double => Type::float(8),
        VbParamType::Bool => Type::int(4, true),
        VbParamType::Bstr => {
            // BSTR = wchar16* (pointer to wide string with length prefix at ptr-4)
            Type::pointer_of_width(&Type::wide_char(2), 4, false, false, None)
        }
        VbParamType::BstrPtr => {
            let bstr = Type::pointer_of_width(&Type::wide_char(2), 4, false, false, None);
            Type::pointer_of_width(&bstr, 4, false, false, None)
        }
        VbParamType::VariantPtr => {
            if let Some(ty) = bv.type_by_name("VARIANT") {
                Type::pointer_of_width(&ty, 4, false, false, None)
            } else {
                ptr32()
            }
        }
        VbParamType::SafeArrayPtr | VbParamType::IUnknownPtr | VbParamType::IDispatchPtr => {
            // Opaque interface pointers — use void* for now
            ptr32()
        }
        VbParamType::SafeArrayPtrPtr
        | VbParamType::IUnknownPtrPtr
        | VbParamType::IDispatchPtrPtr => {
            // Pointer to opaque interface pointer
            Type::pointer_of_width(&ptr32(), 4, false, false, None)
        }
        VbParamType::Hresult => Type::int(4, true),
        VbParamType::GuidPtr => {
            if let Some(ty) = bv.type_by_name("GUID") {
                Type::pointer_of_width(&ty, 4, false, false, None)
            } else {
                ptr32()
            }
        }
        VbParamType::VoidPtr => ptr32(),
        VbParamType::Int32Ptr => Type::pointer_of_width(&Type::int(4, true), 4, false, false, None),
        VbParamType::Int16Ptr => Type::pointer_of_width(&Type::int(2, true), 4, false, false, None),
        VbParamType::UInt8Ptr => {
            Type::pointer_of_width(&Type::int(1, false), 4, false, false, None)
        }
        VbParamType::Int64Ptr => Type::pointer_of_width(&Type::int(8, true), 4, false, false, None),
    }
}

/// Define an auto symbol of the given `kind` at `va`. No-op if `va` is zero.
fn define_symbol(bv: &BinaryView, kind: SymbolType, va: u64, name: &str) {
    if va == 0 {
        return;
    }
    let sym = Symbol::builder(kind, name, va).create();
    bv.define_auto_symbol(&sym);
}
