//! Parse a VB6 PE and extract all metadata into owned structures.
//!
//! The [`visualbasic`] crate uses zero-copy `&'a [u8]` types tied to the raw PE
//! buffer's lifetime. Since Binary Ninja provides data via
//! [`BinaryView::read_vec`] (an owned `Vec<u8>`), we read the entire raw PE,
//! parse it with [`VbProject::from_bytes`], extract everything we need into
//! owned types ([`Vb6AnalysisResult`]), then drop the buffer and parsed
//! structures.
//!
//! The primary entry point is [`analyze`], which returns a
//! [`Vb6AnalysisResult`] containing all VB6 metadata needed by the annotation
//! and architecture modules.

use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use visualbasic::{
    VbProject,
    pcode::{
        calltarget::{CallTarget, ImportResolver},
        operand::Operand,
    },
    project::CodeEntryKind,
    vb::{
        eventname, events::EventSinkVtable, external::ExternalKind, formdata::FormDataHeader,
        property::PropertyValue,
    },
};

/// Top-level analysis result containing all VB6 metadata extracted as owned data.
///
/// Produced by [`analyze`] and consumed by [`crate::annotate::annotate`] to
/// apply types, symbols, functions, and comments to the [`BinaryView`].
pub struct Vb6AnalysisResult {
    /// Whether the project uses P-Code (vs. native compilation).
    pub is_pcode: bool,
    /// VB6 project name from the object table.
    pub project_name: String,
    /// VA of the `VbHeader` (`EXEPROJECTINFO`) structure (0x68 bytes).
    pub vb_header_va: u64,
    /// VA of the `ProjectData` structure (0x23C bytes).
    pub project_data_va: u64,
    /// VA of the `ObjectTable` structure (0x54 bytes).
    pub object_table_va: u64,
    /// VA of the GUI component table from `VbHeader.lpGuiTable`.
    pub gui_table_va: u64,
    /// VA of the COM registration data from `VbHeader.lpComRegisterData`.
    pub com_register_data_va: u64,
    /// VA of the `ProjectData` external table (Declare function imports).
    pub proj_ext_table_va: u64,
    /// VA of the `ProjectInfo2` structure from `ObjectTable.lpProjectInfo2`.
    pub project_info2_va: Option<u64>,
    /// Number of forms/visual objects in the GUI table.
    #[allow(dead_code)]
    pub form_count: u16,
    /// Number of external table entries.
    #[allow(dead_code)]
    pub external_count: u16,
    /// Per-GUI-table-entry VAs (one per form/UserControl/MDIForm).
    pub gui_entry_vas: Vec<u64>,
    /// Per-ComRegObject VAs in the COM registration linked list.
    pub com_reg_object_vas: Vec<u64>,
    /// GUID arrays from COM registration: `(va, count, label)`.
    pub com_reg_guid_arrays: Vec<(u64, u32, String)>,
    /// ANSI string VAs from VbHeader and COM registration data: `(va, label, string)`.
    pub data_strings: Vec<(u64, String, String)>,
    /// Per-external-table-entry info VAs with type classification.
    pub external_entry_info: Vec<ExternalEntryInfo>,
    /// Pre-resolved Declare imports, indexed by external table position.
    pub resolved_imports: Vec<Option<ResolvedImport>>,
    /// Pre-resolved import names, indexed parallel to `resolved_imports`.
    pub resolved_import_names: Vec<Option<String>>,
    /// Pre-resolved constant pool strings: `(data_const_va, offset, string)`.
    pub resolved_const_strings: Vec<(u64, u16, String)>,
    /// Per-object analysis data.
    pub objects: Vec<ObjectAnalysis>,
    /// Parsed form designer data for visual objects.
    pub forms: Vec<FormAnalysis>,
}

/// A resolved VB6 `Declare` function import (DLL API call).
///
/// Produced by [`ImportResolver::resolve_external`] during analysis and used
/// during annotation to create named symbols at external table entry VAs.
pub struct ResolvedImport {
    /// DLL library name (e.g., `"kernel32"`).
    pub library: String,
    /// API function name (e.g., `"CreateFileA"`).
    pub function: String,
}

/// Information about an external table entry's info structure.
pub struct ExternalEntryInfo {
    /// VA of the ExternalDeclareInfo or ExternalTypelibInfo structure.
    pub info_va: u64,
    /// Whether this is a Declare function (true) or TypeLib (false).
    pub is_declare: bool,
}

/// Analysis data for a single VB6 object (form, module, class, etc.).
pub struct ObjectAnalysis {
    /// Object name from the name table.
    pub name: String,
    /// Object kind as a display string (e.g., `"Form"`, `"Module"`, `"Class"`).
    #[allow(dead_code)]
    pub kind: String,
    /// Index of this object in the object array.
    pub object_index: u16,
    /// VA of this object's `PublicObjectDescriptor` (0x30 bytes).
    pub descriptor_va: u64,
    /// VA of this object's `ObjectInfo` structure (0x38 bytes).
    pub object_info_va: u64,
    /// VA of the `OptionalObjectInfo` (0x40 bytes), if present.
    pub optional_info_va: Option<u64>,
    /// VA of the `PrivateObjectDescriptor` (0x40 bytes), if present.
    pub private_object_va: Option<u64>,
    /// VA of the method dispatch table (`u32[]` of method entry VAs).
    pub methods_table_va: u64,
    /// Number of entries in the method dispatch table.
    pub method_count: u16,
    /// VA of the constants pool (`void*[]` array).
    pub constants_va: u64,
    /// Number of entries in the constants pool.
    pub constants_count: u16,
    /// All code entry points discovered by [`code_entries()`].
    ///
    /// Includes P-Code methods, native methods, native thunks (from method
    /// link tables), and event handlers (from control event sink vtables).
    ///
    /// [`code_entries()`]: visualbasic::project::VbObject::code_entries
    pub code_entries: Vec<CodeEntryAnalysis>,
    /// Controls (GUI elements) belonging to this object.
    pub controls: Vec<ControlAnalysis>,
    /// VAs of FuncTypDesc structures for this object.
    pub func_type_desc_vas: Vec<u64>,
    /// VA of the FuncTypDesc pointer table (array of `void*`).
    pub func_type_descs_table_va: u64,
    /// Total number of entries in the FuncTypDesc pointer table.
    pub func_type_desc_table_count: u16,
    /// Data extracted from OptionalObjectInfo, if present.
    pub optional_info_data: Option<OptionalInfoData>,
    /// VA of the method names table (`void*[method_count]`).
    pub method_names_va: u64,
    /// VA of the object name string (null-terminated ANSI).
    pub object_name_va: u64,
    /// Resolved BSTRs from the constants pool: `(bstr_va, byte_length)`.
    pub const_pool_bstrs: Vec<(u64, u32)>,
    /// Resolved GUIDs pointed to by GUID tables: `guid_va`.
    pub guid_data_vas: Vec<u64>,
}

/// An extracted code entry point from the [`code_entries()`] API.
///
/// For P-Code entries, the additional metadata fields ([`stub_va`],
/// [`data_const_va`], [`pcode_size`]) are populated from the corresponding
/// [`CodeEntry`] fields. The `ProcDscInfo` VA can be computed as
/// `va + pcode_size` since it immediately follows the P-Code byte stream.
///
/// [`code_entries()`]: visualbasic::project::VbObject::code_entries
/// [`CodeEntry`]: visualbasic::project::CodeEntry
/// [`stub_va`]: Self::stub_va
/// [`data_const_va`]: Self::data_const_va
/// [`pcode_size`]: Self::pcode_size
pub struct CodeEntryAnalysis {
    /// Virtual address of the code entry point.
    pub va: u64,
    /// Classification of this entry (P-Code, native, thunk, or event handler).
    pub kind: CodeEntryKindOwned,
    /// Human-readable name (e.g., `"Click"`, `"Timer1_Timer"`), or `None`.
    pub name: Option<String>,
    /// Index of the parent VB6 object.
    pub object_index: u16,
    /// VA of the P-Code call stub.
    pub stub_va: Option<u64>,
    /// Constant pool base VA for resolving string and import references.
    pub data_const_va: Option<u64>,
    /// Size of the P-Code byte stream in bytes.
    pub pcode_size: Option<u16>,
}

/// Owned copy of [`CodeEntryKind`] that outlives the parse buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeEntryKindOwned {
    PCode,
    Native,
    NativeThunk,
    EventHandler,
}

impl From<CodeEntryKind> for CodeEntryKindOwned {
    fn from(k: CodeEntryKind) -> Self {
        match k {
            CodeEntryKind::PCode => CodeEntryKindOwned::PCode,
            CodeEntryKind::Native => CodeEntryKindOwned::Native,
            CodeEntryKind::NativeThunk => CodeEntryKindOwned::NativeThunk,
            CodeEntryKind::EventHandler => CodeEntryKindOwned::EventHandler,
        }
    }
}

/// Analysis data for a GUI control belonging to a VB6 object.
pub struct ControlAnalysis {
    /// Control name (e.g., `"Timer1"`, `"Command1"`).
    pub name: String,
    /// VA of the `ControlInfo` structure (0x28 bytes).
    pub control_info_va: u64,
    /// VA of the event sink vtable (`void*[]` array).
    pub event_sink_vtable_va: u64,
    /// Number of slots in the event sink vtable.
    pub event_handler_slots: u16,
    /// VA of the control's GUID (16 bytes).
    pub guid_va: u64,
    /// Resolved event slot names (index → event name), empty slots omitted.
    pub event_slot_names: Vec<(u16, String)>,
    /// IUnknown thunk VAs from vtable header: (QueryInterface, AddRef, Release).
    pub iunknown_thunk_vas: (u64, u64, u64),
}

/// Data extracted from an `OptionalObjectInfo` structure.
pub struct OptionalInfoData {
    /// VA of the object's CLSID (16 bytes).
    pub object_clsid_va: u64,
    /// VA of the GUI GUID table and its entry count.
    pub gui_guid_table_va: u64,
    pub gui_guids_count: u32,
    /// VA of the default IID table and its entry count.
    pub default_iid_table_va: u64,
    pub default_iid_count: u32,
    /// VA of the events IID table and its entry count.
    pub events_iid_table_va: u64,
    pub events_iid_count: u32,
    /// VA of the method link table and its entry count.
    pub method_link_table_va: u64,
    pub method_link_count: u16,
}

/// Parsed form designer data for a single visual object.
pub struct FormAnalysis {
    /// Parent object name (e.g., `"Form1"`).
    pub object_name: String,
    /// VA of the form binary data blob.
    pub form_data_va: u64,
    /// Total size of the form data blob.
    #[allow(dead_code)]
    pub form_data_size: u32,
    /// Form width in twips.
    pub width: u32,
    /// Form height in twips.
    pub height: u32,
    /// Form-level decoded properties.
    pub form_properties: Vec<OwnedProperty>,
    /// Child controls in parse order.
    pub controls: Vec<FormControlAnalysis>,
    /// Embedded picture/icon blobs.
    pub resources: Vec<EmbeddedResourceInfo>,
}

/// A child control from the form binary data.
pub struct FormControlAnalysis {
    /// Control name (e.g., `"Timer1"`).
    pub name: String,
    /// Control type name (e.g., `"Timer"`).
    pub control_type: String,
    /// Nesting depth (0 = top-level).
    pub depth: u16,
    /// Byte offset of the record within the form data blob.
    pub record_offset: u32,
    /// Total record size in bytes.
    pub record_size: u32,
    /// Decoded properties.
    pub properties: Vec<OwnedProperty>,
    /// Event handler names linked to this control (e.g., `["Timer1_Timer"]`).
    pub event_handlers: Vec<(String, u64)>,
}

/// A decoded property name+value pair.
pub struct OwnedProperty {
    /// Property name (e.g., `"Interval"`).
    pub name: String,
    /// Display-formatted value (e.g., `"1000"`).
    pub value: String,
}

/// An embedded picture/icon resource within form data.
pub struct EmbeddedResourceInfo {
    /// Control or form name owning the resource.
    pub control_name: String,
    /// Property name (e.g., `"Picture"`, `"Icon"`).
    pub property_name: String,
    /// Byte offset within the form data blob (of the size prefix).
    pub offset_in_form: u32,
    /// Picture data size in bytes (excluding the 4-byte prefix).
    pub size: u32,
    /// Whether the data starts with a BMP header.
    pub is_bmp: bool,
}

/// Parse a VB6 PE from the [`BinaryView`]'s raw parent view and extract all
/// metadata into owned structures.
pub fn analyze(bv: &BinaryView) -> Result<Vb6AnalysisResult, String> {
    let raw_view = bv.raw_view().ok_or("No raw/parent view available")?;
    let raw_len = raw_view.len() as usize;
    if raw_len == 0 {
        return Err("Raw view is empty".into());
    }
    let raw_bytes = raw_view.read_vec(0, raw_len);
    if raw_bytes.len() < raw_len {
        return Err(format!(
            "Could only read {} of {} bytes from raw view",
            raw_bytes.len(),
            raw_len
        ));
    }

    let project = VbProject::from_bytes(&raw_bytes).map_err(|e| format!("VB6 parse error: {e}"))?;

    let is_pcode = project.is_pcode();
    let project_name = project
        .project_name()
        .ok()
        .and_then(|b| std::str::from_utf8(b).ok())
        .unwrap_or("<unknown>")
        .to_string();

    let header = project.vb_header();
    let proj_data = project.project_data();
    let obj_table = project.object_table();
    let map = project.address_map();

    let vb_header_va = find_vb_header_va(bv).unwrap_or(0);
    let project_data_va = header.project_data_va() as u64;
    let object_table_va = proj_data.object_table_va() as u64;
    let object_array_va = obj_table.object_array_va() as u64;
    let gui_table_va = header.gui_table_va() as u64;
    let com_register_data_va = header.com_register_data_va() as u64;

    let form_count = header.form_count();
    let external_count_header = header.external_count();

    // Collect all inline ANSI strings: VbHeader, ComRegData, ComRegObject.
    let mut data_strings: Vec<(u64, String, String)> = Vec::new();

    // VbHeader self-relative inline strings (+0x58..+0x64).
    if vb_header_va != 0 {
        let hdr_va = vb_header_va as u32;
        let hdr_strings: &[(&str, u32)] = &[
            ("ProjectDescription", header.project_description_offset()),
            ("ProjectExeName", header.project_exe_name_offset()),
            ("ProjectHelpFile", header.project_help_file_offset()),
            ("ProjectName", header.project_name_offset()),
        ];
        for &(label, off) in hdr_strings {
            if off == 0 {
                continue;
            }
            let str_va = hdr_va.wrapping_add(off);
            if let Ok(data) = map.slice_from_va(str_va, 256) {
                let end = data.iter().position(|&b| b == 0).unwrap_or(0);
                if end > 0 {
                    let s = String::from_utf8_lossy(&data[..end]).into_owned();
                    data_strings.push((str_va as u64, format!("vb6::VbHeader::{label}"), s));
                }
            }
        }
    }

    // Walk the ComRegData linked list to collect ComRegObject VAs and strings.
    let mut com_reg_object_vas = Vec::new();
    let mut com_reg_guid_arrays: Vec<(u64, u32, String)> = Vec::new();
    if com_register_data_va != 0 {
        use visualbasic::vb::comreg::ComRegData;
        let com_va = com_register_data_va as u32;
        if let Ok(data) = map.slice_from_va(com_va, ComRegData::HEADER_SIZE) {
            if let Ok(com_reg) = ComRegData::parse(data, com_va) {
                // ComRegData strings (self-relative from com_va)
                if let Some(s) = com_reg.project_name(map) {
                    let off = com_reg.project_name_offset();
                    data_strings.push((
                        (com_va + off) as u64,
                        "vb6::ComRegData::ProjectName".into(),
                        s.to_string(),
                    ));
                }
                if let Some(s) = com_reg.help_dir(map) {
                    let off = com_reg.help_dir_offset();
                    data_strings.push((
                        (com_va + off) as u64,
                        "vb6::ComRegData::HelpDir".into(),
                        s.to_string(),
                    ));
                }
                let desc_off = com_reg.description_offset();
                if desc_off != 0 {
                    if let Ok(desc_data) = map.slice_from_va(com_va + desc_off, 256) {
                        let end = desc_data.iter().position(|&b| b == 0).unwrap_or(0);
                        if end > 0 {
                            let s = String::from_utf8_lossy(&desc_data[..end]).into_owned();
                            data_strings.push((
                                (com_va + desc_off) as u64,
                                "vb6::ComRegData::Description".into(),
                                s,
                            ));
                        }
                    }
                }

                // ComRegObject VAs, strings, and interface GUID arrays
                for obj in com_reg.objects(map) {
                    com_reg_object_vas.push(obj.va() as u64);
                    let obj_name = obj.object_name(map).unwrap_or("?");
                    if let Some(s) = obj.object_name(map) {
                        let off = obj.object_name_offset();
                        data_strings.push((
                            (com_va + off) as u64,
                            format!("vb6::ComRegObject::Name::{obj_name}"),
                            s.to_string(),
                        ));
                    }
                    if let Some(s) = obj.description(map) {
                        let off = obj.description_offset();
                        data_strings.push((
                            (com_va + off) as u64,
                            format!("vb6::ComRegObject::Desc::{obj_name}"),
                            s.to_string(),
                        ));
                    }
                    // Default and source interface GUID arrays
                    let def_off = obj.default_iface_guids_offset();
                    let def_count = obj.default_iface_count();
                    if def_off != 0 && def_count > 0 {
                        com_reg_guid_arrays.push((
                            (com_va + def_off) as u64,
                            def_count,
                            format!("vb6::ComRegObject::DefaultIfaces::{obj_name}"),
                        ));
                    }
                    let src_off = obj.source_iface_guids_offset();
                    let src_count = obj.source_iface_count();
                    if src_off != 0 && src_count > 0 {
                        com_reg_guid_arrays.push((
                            (com_va + src_off) as u64,
                            src_count,
                            format!("vb6::ComRegObject::SourceIfaces::{obj_name}"),
                        ));
                    }
                }
            }
        }
    }

    // ProjectInfo2 VA from ObjectTable
    let pi2_va = obj_table.project_info2_va();
    let project_info2_va = if pi2_va != 0 && pi2_va != 0xFFFFFFFF {
        Some(pi2_va as u64)
    } else {
        None
    };

    // Collect GUI table entries via the crate's iterator.
    let gui_entries: Vec<_> = project.gui_entries().collect();
    let gui_entry_vas: Vec<u64> = gui_entries.iter().map(|ge| ge.va() as u64).collect();

    let mut objects = Vec::new();
    let mut resolved_const_strings = Vec::new();
    let mut forms = Vec::new();
    let mut gui_entry_index: usize = 0;

    for (obj_idx, obj_result) in project.objects().enumerate() {
        let obj = match obj_result {
            Ok(o) => o,
            Err(_) => continue,
        };

        let name = obj
            .name()
            .ok()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("<unnamed>")
            .to_string();

        let desc = obj.descriptor();
        let info = obj.info();

        let descriptor_va = object_array_va + (obj_idx as u64) * 0x30;
        let object_info_va = desc.object_info_va() as u64;
        let optional_info_va = obj.optional_info().map(|_| object_info_va + 0x38);
        let private_object_va = obj.private_object().and_then(|_| {
            let va = info.private_object_va();
            if va == 0 || va == 0xFFFFFFFF {
                None
            } else {
                Some(va as u64)
            }
        });

        let methods_table_va = info.methods_va() as u64;
        let method_count = obj.method_count();
        let constants_va = info.constants_va() as u64;
        let constants_count = info.constants_count();

        // Parse form data for visual objects (forms, UserControls, MDIForms).
        let gui_entry = if obj.object_type_flags().is_form() && gui_entry_index < gui_entries.len()
        {
            let ge = &gui_entries[gui_entry_index];
            gui_entry_index += 1;
            Some(ge)
        } else {
            None
        };
        let form_data = gui_entry.and_then(|ge| obj.form_data_from_gui_entry(ge));

        let code_entries: Vec<CodeEntryAnalysis> = obj
            .code_entries(form_data.as_ref())
            .into_iter()
            .map(|ce| CodeEntryAnalysis {
                va: ce.va as u64,
                kind: ce.kind.into(),
                name: ce.name,
                object_index: obj_idx as u16,
                stub_va: ce.stub_va.map(|v| v as u64),
                data_const_va: ce.data_const_va.map(|v| v as u64),
                pcode_size: ce.pcode_size,
            })
            .collect();

        let mut controls = Vec::new();
        for (c_idx, ctrl_result) in obj.controls().enumerate() {
            let ctrl = match ctrl_result {
                Ok(c) => c,
                Err(_) => continue,
            };

            let ctrl_name = std::str::from_utf8(ctrl.name())
                .unwrap_or("<unnamed>")
                .to_string();

            let control_info_va = obj
                .optional_info()
                .map(|opt| opt.controls_va() as u64 + (c_idx as u64) * 0x28)
                .unwrap_or(0);

            // Resolve event slot names and IUnknown thunk VAs from vtable
            let ci = ctrl.info();
            let slots = ci.event_handler_slots();
            let vtable_va = ci.event_sink_vtable_va();
            let ctrl_type = ctrl.form_control_type().or_else(|| {
                ctrl.class_name()
                    .and_then(visualbasic::vb::formdata::FormControlType::from_class_name)
            });

            let mut event_slot_names = Vec::new();
            for slot in 0..slots {
                let name = ctrl_type
                    .and_then(|ct| eventname::event_name(slot, ct))
                    .or_else(|| eventname::standard_event_name(slot));
                if let Some(en) = name {
                    event_slot_names.push((slot, en.to_string()));
                }
            }

            let iunknown_thunk_vas = if vtable_va != 0 {
                let vtable_size = EventSinkVtable::HEADER_SIZE + slots as usize * 4;
                map.slice_from_va(vtable_va, vtable_size)
                    .ok()
                    .and_then(|d| EventSinkVtable::parse(d, slots).ok())
                    .map(|vt| {
                        (
                            vt.query_interface_va() as u64,
                            vt.add_ref_va() as u64,
                            vt.release_va() as u64,
                        )
                    })
                    .unwrap_or((0, 0, 0))
            } else {
                (0, 0, 0)
            };

            controls.push(ControlAnalysis {
                name: ctrl_name,
                control_info_va,
                event_sink_vtable_va: vtable_va as u64,
                event_handler_slots: slots,
                guid_va: ci.guid_va() as u64,
                event_slot_names,
                iunknown_thunk_vas,
            });
        }

        // Extract FuncTypDesc VAs from PrivateObjectDescriptor
        let mut func_type_desc_vas = Vec::new();
        let mut func_type_descs_table_va = 0u64;
        let mut func_type_desc_table_count = 0u16;
        if let Some(priv_obj) = obj.private_object() {
            let ftd_table_va = priv_obj.func_type_descs_va();
            let func_count = priv_obj.func_count();
            let var_count = priv_obj.var_count();
            let total_count = func_count + var_count;
            if ftd_table_va != 0 && total_count > 0 {
                func_type_descs_table_va = ftd_table_va as u64;
                func_type_desc_table_count = total_count;
                for i in 0..func_count {
                    let ptr_va = ftd_table_va + (i as u32) * 4;
                    if let Ok(data) = map.slice_from_va(ptr_va, 4) {
                        let ftd_va = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                        if ftd_va != 0 {
                            func_type_desc_vas.push(ftd_va as u64);
                        }
                    }
                }
            }
        }

        let method_names_va = desc.method_names_va() as u64;
        let object_name_va = desc.object_name_va() as u64;

        // Resolve BSTRs from constants pool (for typing string data in the binary)
        let const_pool_bstrs: Vec<(u64, u32)> = if constants_va != 0 && constants_count > 0 {
            obj.constants_pool()
                .bstr_entries(constants_count)
                .map(|b| (b.va() as u64, b.byte_length()))
                .collect()
        } else {
            Vec::new()
        };

        // Collect individual GUID VAs from OptionalObjectInfo GUID tables
        let mut guid_data_vas = Vec::new();
        for (guid_va, _) in obj.gui_guids() {
            guid_data_vas.push(guid_va as u64);
        }
        for (guid_va, _) in obj.default_iids() {
            guid_data_vas.push(guid_va as u64);
        }
        for (guid_va, _) in obj.events_iids() {
            guid_data_vas.push(guid_va as u64);
        }
        if let Some(clsid_va) = obj
            .optional_info()
            .map(|o| o.object_clsid_va())
            .filter(|&v| v != 0)
        {
            guid_data_vas.push(clsid_va as u64);
        }

        // Extract OptionalObjectInfo data
        let optional_info_data = obj.optional_info().map(|opt| OptionalInfoData {
            object_clsid_va: opt.object_clsid_va() as u64,
            gui_guid_table_va: opt.gui_guid_table_va() as u64,
            gui_guids_count: opt.gui_guids_count(),
            default_iid_table_va: opt.default_iid_table_va() as u64,
            default_iid_count: opt.default_iid_count(),
            events_iid_table_va: opt.events_iid_table_va() as u64,
            events_iid_count: opt.events_iid_count(),
            method_link_table_va: opt.method_link_table_va() as u64,
            method_link_count: opt.method_link_count(),
        });

        // Pre-resolve constant pool strings by scanning P-Code instructions
        // for `%s` operands and resolving them via the constant pool.
        if is_pcode {
            for method_result in obj.pcode_methods() {
                let method = match method_result {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let pool = method.constant_pool(map);
                let data_const_va = method.data_const_va() as u64;
                for insn_result in method.instructions() {
                    let insn = match insn_result {
                        Ok(i) => i,
                        Err(_) => continue,
                    };
                    for op in insn.operands.iter().flatten() {
                        if let Operand::ConstPoolIndex(idx) = op {
                            if let Ok(Some(s)) = pool.resolve_string(*idx) {
                                resolved_const_strings.push((data_const_va, *idx, s));
                            }
                        }
                    }
                }
            }
        }

        // Extract form data for visual objects.
        if let (Some(fd), Some(ge)) = (&form_data, gui_entry) {
            let header = fd.header();
            let fd_va = ge.form_data_va() as u64;
            let fd_size = ge.form_data_size();

            // Decode form-level properties (use Form type as default)
            let form_type = visualbasic::vb::formdata::FormControlType::Form;
            let form_props: Vec<OwnedProperty> = fd
                .form_properties_decoded(form_type)
                .map(|p| OwnedProperty {
                    name: p.name.to_string(),
                    value: format!("{}", p.value),
                })
                .collect();

            // Build per-control analysis
            let mut form_controls = Vec::new();
            let mut resources = Vec::new();

            for ctrl in fd.controls() {
                let ctrl_name = std::str::from_utf8(ctrl.name()).unwrap_or("?").to_string();
                let ctrl_type = ctrl.control_type().name().to_string();
                let rec_offset = ctrl.offset_in_blob();
                let rec_size = ctrl.total_size();

                // Decode properties, track picture resources
                let mut props = Vec::new();
                for p in ctrl.properties() {
                    if let PropertyValue::Picture(ref pic) = p.value {
                        if !pic.is_default && pic.size > 0 {
                            let pic_off = ctrl.properties_offset_in_blob() as usize + p.offset;
                            resources.push(EmbeddedResourceInfo {
                                control_name: ctrl_name.clone(),
                                property_name: p.name.to_string(),
                                offset_in_form: pic_off as u32,
                                size: pic.size,
                                is_bmp: pic.is_bmp,
                            });
                        }
                    }
                    props.push(OwnedProperty {
                        name: p.name.to_string(),
                        value: format!("{}", p.value),
                    });
                }

                // Cross-reference event handlers by name prefix
                let prefix = format!("{ctrl_name}_");
                let handlers: Vec<(String, u64)> = code_entries
                    .iter()
                    .filter(|ce| {
                        ce.kind == CodeEntryKindOwned::EventHandler
                            && ce.name.as_deref().unwrap_or("").starts_with(&prefix)
                    })
                    .map(|ce| (ce.name.clone().unwrap_or_default(), ce.va))
                    .collect();

                form_controls.push(FormControlAnalysis {
                    name: ctrl_name,
                    control_type: ctrl_type,
                    depth: ctrl.depth(),
                    record_offset: rec_offset,
                    record_size: rec_size,
                    properties: props,
                    event_handlers: handlers,
                });
            }

            // Also check form-level properties for pictures (Icon, Picture)
            for p in fd.form_properties_decoded(form_type) {
                if let PropertyValue::Picture(ref pic) = p.value {
                    if !pic.is_default && pic.size > 0 {
                        let pic_off = FormDataHeader::MIN_SIZE + p.offset;
                        resources.push(EmbeddedResourceInfo {
                            control_name: name.clone(),
                            property_name: p.name.to_string(),
                            offset_in_form: pic_off as u32,
                            size: pic.size,
                            is_bmp: pic.is_bmp,
                        });
                    }
                }
            }

            forms.push(FormAnalysis {
                object_name: name.clone(),
                form_data_va: fd_va,
                form_data_size: fd_size,
                width: header.width(),
                height: header.height(),
                form_properties: form_props,
                controls: form_controls,
                resources,
            });
        }

        objects.push(ObjectAnalysis {
            name,
            kind: obj.object_kind().to_string(),
            object_index: obj_idx as u16,
            descriptor_va,
            object_info_va,
            optional_info_va,
            private_object_va,
            methods_table_va,
            method_count,
            constants_va,
            constants_count,
            code_entries,
            controls,
            func_type_desc_vas,
            func_type_descs_table_va,
            func_type_desc_table_count,
            optional_info_data,
            method_names_va,
            object_name_va,
            const_pool_bstrs,
            guid_data_vas,
        });
    }

    let proj_ext_table_va = proj_data.external_table_va() as u64;
    let ext_count = proj_data.external_count();
    let resolver = ImportResolver::from_project(&project);
    let mut resolved_imports = Vec::with_capacity(ext_count as usize);
    let mut resolved_import_names = Vec::with_capacity(ext_count as usize);
    let mut external_entry_info = Vec::with_capacity(ext_count as usize);

    for (i, ext_result) in project.externals().enumerate() {
        let ext = match ext_result {
            Ok(e) => e,
            Err(_) => {
                resolved_imports.push(None);
                resolved_import_names.push(None);
                continue;
            }
        };

        let info_va = ext.external_object_va() as u64;
        let is_declare = matches!(ext.kind(), ExternalKind::DeclareFunction);
        external_entry_info.push(ExternalEntryInfo {
            info_va,
            is_declare,
        });

        match resolver.resolve_external(i as u16) {
            CallTarget::Api { library, function } => {
                let name = format!("{}!{}", library, function);
                resolved_import_names.push(Some(name));
                resolved_imports.push(Some(ResolvedImport { library, function }));
            }
            _ => {
                // Try to resolve as typelib GUID
                if matches!(ext.kind(), ExternalKind::TypeLib) {
                    if let Some(typelib) = ext.as_typelib(map) {
                        if let Some(guid) = typelib.typelib_guid(map) {
                            let name = format!("typelib:{}", guid);
                            resolved_import_names.push(Some(name.clone()));
                            resolved_imports.push(Some(ResolvedImport {
                                library: "typelib".to_string(),
                                function: guid.to_string(),
                            }));
                            continue;
                        }
                    }
                }
                resolved_imports.push(None);
                resolved_import_names.push(None);
            }
        }
    }

    Ok(Vb6AnalysisResult {
        is_pcode,
        project_name,
        vb_header_va,
        project_data_va,
        object_table_va,
        gui_table_va,
        com_register_data_va,
        com_reg_object_vas,
        com_reg_guid_arrays,
        data_strings,
        proj_ext_table_va,
        project_info2_va,
        form_count,
        external_count: external_count_header,
        gui_entry_vas,
        external_entry_info,
        resolved_imports,
        resolved_import_names,
        resolved_const_strings,
        objects,
        forms,
    })
}

/// Locate the `VbHeader` VA by reading the PE entry point's `push imm32` operand.
fn find_vb_header_va(bv: &BinaryView) -> Option<u64> {
    let entry = bv.entry_point();
    let mut buf = [0u8; 6];
    if bv.read(&mut buf, entry) < 6 {
        return None;
    }
    if buf[0] == 0x68 {
        let va = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
        return Some(va as u64);
    }
    None
}
