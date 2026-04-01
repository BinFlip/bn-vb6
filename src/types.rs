//! Define VB6 structure and enum types in Binary Ninja's type system.
//!
//! Each function creates a named type matching a VB6 internal structure or
//! enumeration and registers it with the [`BinaryView`] via `define_auto_type`.
//! Types use the `"vb6"` type source identifier and are named with a `VB6_`
//! prefix (e.g., `VB6_VbHeader`, `VB6_ObjectTypeFlags`).
//!
//! These types are applied as data variable overlays by
//! [`crate::annotate::apply_struct_overlays`].

use std::num::NonZeroUsize;

use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    rc::Ref,
    types::{EnumerationBuilder, MemberAccess, MemberScope, StructureBuilder, Type},
};

const A: MemberAccess = MemberAccess::PublicAccess;
const S: MemberScope = MemberScope::NoScope;

fn ptr32() -> Ref<Type> {
    Type::pointer_of_width(&Type::void(), 4, false, false, None)
}

fn u16_ty() -> Ref<Type> {
    Type::int(2, false)
}

fn u32_ty() -> Ref<Type> {
    Type::int(4, false)
}

fn u8_ty() -> Ref<Type> {
    Type::int(1, false)
}

fn char_array(n: u64) -> Ref<Type> {
    Type::array(&Type::char(), n)
}

fn u8_array(n: u64) -> Ref<Type> {
    Type::array(&Type::int(1, false), n)
}

fn build_and_register(bv: &BinaryView, name: &str, sb: &mut StructureBuilder) {
    let structure = sb.finalize();
    let ty = Type::structure(&structure);
    bv.define_auto_type(name, "vb6", &ty);
}

/// Insert a field into a [`StructureBuilder`], keeping the [`Ref<Type>`] alive
/// for the borrow.
macro_rules! field {
    ($sb:expr, $ty_expr:expr, $name:expr, $offset:expr) => {{
        let ty = $ty_expr;
        $sb.insert(&*ty, $name, $offset, true, A, S);
    }};
}

/// Register all VB6 types (15 structs + 4 enums) with the [`BinaryView`].
///
/// Called once during annotation before struct overlays are applied.
pub fn define_all_types(bv: &BinaryView) {
    define_object_type_flags_enum(bv);
    define_vb_base_type_enum(bv);
    define_form_control_type_enum(bv);
    define_proc_opt_flags_enum(bv);
    define_vb_header_type(bv);
    define_project_data_type(bv);
    define_object_table_type(bv);
    define_public_object_descriptor_type(bv);
    define_object_info_type(bv);
    define_optional_object_info_type(bv);
    define_private_object_descriptor_type(bv);
    define_proc_dsc_info_type(bv);
    define_control_info_type(bv);
    define_gui_table_entry_type(bv);
    define_com_reg_data_type(bv);
    define_project_info2_type(bv);
    define_func_typ_desc_type(bv);
    define_external_declare_info_type(bv);
    define_external_typelib_info_type(bv);
    define_cleanup_table_header_type(bv);
    define_com_reg_object_type(bv);
    define_variant_type(bv);
    define_guid_struct_type(bv);
    define_form_data_header_type(bv);
}

/// `ObjectTypeFlags` — bitfield from `PublicObjectDescriptor.fObjectType`.
fn define_object_type_flags_enum(bv: &BinaryView) {
    let mut eb = EnumerationBuilder::new();
    eb.insert("HAS_OPTIONAL_INFO", 0x01);
    eb.insert("HAS_COM_INTERFACE", 0x02);
    eb.insert("IS_VISUAL", 0x80);
    eb.insert("ACTIVEX", 0x800);
    let ty = Type::enumeration(&eb.finalize(), NonZeroUsize::new(4).unwrap(), false);
    bv.define_auto_type("VB6_ObjectTypeFlags", "vb6", &ty);
}

/// `VbBaseType` — 5-bit type codes for variable/parameter types.
fn define_vb_base_type_enum(bv: &BinaryView) {
    let mut eb = EnumerationBuilder::new();
    eb.insert("Void", 0x00);
    eb.insert("Null", 0x01);
    eb.insert("Integer", 0x02);
    eb.insert("Long", 0x03);
    eb.insert("Single", 0x04);
    eb.insert("Double", 0x05);
    eb.insert("Currency", 0x06);
    eb.insert("Date", 0x07);
    eb.insert("String", 0x08);
    eb.insert("Object", 0x0A);
    eb.insert("Error", 0x0B);
    eb.insert("Boolean", 0x0C);
    eb.insert("Variant", 0x0D);
    eb.insert("Decimal", 0x0E);
    eb.insert("Byte", 0x10);
    eb.insert("Udt", 0x11);
    eb.insert("TypedObject", 0x13);
    eb.insert("TypedArray", 0x14);
    eb.insert("LongPtr", 0x1B);
    eb.insert("ExtDecimal", 0x1C);
    eb.insert("ExternalCom", 0x1D);
    eb.insert("DispatchPtr", 0x1E);
    let ty = Type::enumeration(&eb.finalize(), NonZeroUsize::new(1).unwrap(), false);
    bv.define_auto_type("VB6_VbBaseType", "vb6", &ty);
}

/// `FormControlType` — control type codes from form binary data `cType`.
fn define_form_control_type_enum(bv: &BinaryView) {
    let mut eb = EnumerationBuilder::new();
    eb.insert("PictureBox", 0);
    eb.insert("Label", 1);
    eb.insert("TextBox", 2);
    eb.insert("Frame", 3);
    eb.insert("CommandButton", 4);
    eb.insert("CheckBox", 5);
    eb.insert("OptionButton", 6);
    eb.insert("ComboBox", 7);
    eb.insert("ListBox", 8);
    eb.insert("HScrollBar", 9);
    eb.insert("VScrollBar", 10);
    eb.insert("Timer", 11);
    eb.insert("Form", 13);
    eb.insert("DriveListBox", 16);
    eb.insert("DirListBox", 17);
    eb.insert("FileListBox", 18);
    eb.insert("Menu", 19);
    eb.insert("MDIForm", 20);
    eb.insert("Shape", 22);
    eb.insert("Line", 23);
    eb.insert("Image", 24);
    eb.insert("Data", 37);
    eb.insert("OLE", 38);
    eb.insert("UserControl", 40);
    eb.insert("PropertyPage", 41);
    eb.insert("UserDocument", 42);
    let ty = Type::enumeration(&eb.finalize(), NonZeroUsize::new(1).unwrap(), false);
    bv.define_auto_type("VB6_FormControlType", "vb6", &ty);
}

/// `ProcOptFlags` — procedure option bitfield from `ProcDscInfo` offset 0x0C.
fn define_proc_opt_flags_enum(bv: &BinaryView) {
    let mut eb = EnumerationBuilder::new();
    eb.insert("HAS_ERROR_HANDLER", 0x10);
    eb.insert("HAS_RESUME_NEXT", 0x20);
    let ty = Type::enumeration(&eb.finalize(), NonZeroUsize::new(2).unwrap(), false);
    bv.define_auto_type("VB6_ProcOptFlags", "vb6", &ty);
}

/// `VbHeader` (aka `EXEPROJECTINFO`) — 0x68 bytes.
fn define_vb_header_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, char_array(4), "szVbMagic", 0x00);
    field!(sb, u16_ty(), "wRuntimeBuild", 0x04);
    field!(sb, char_array(14), "szLangDll", 0x06);
    field!(sb, char_array(14), "szSecLangDll", 0x14);
    field!(sb, u16_ty(), "wRuntimeRevision", 0x22);
    field!(sb, u32_ty(), "dwLCID", 0x24);
    field!(sb, u32_ty(), "dwSecLCID", 0x28);
    field!(sb, ptr32(), "lpSubMain", 0x2C);
    field!(sb, ptr32(), "lpProjectData", 0x30);
    field!(sb, u32_ty(), "fMdlIntCtls", 0x34);
    field!(sb, u32_ty(), "fMdlIntCtls2", 0x38);
    field!(sb, u32_ty(), "dwThreadFlags", 0x3C);
    field!(sb, u32_ty(), "dwThreadCount", 0x40);
    field!(sb, u16_ty(), "wFormCount", 0x44);
    field!(sb, u16_ty(), "wExternalCount", 0x46);
    field!(sb, u32_ty(), "dwThunkCount", 0x48);
    field!(sb, ptr32(), "lpGuiTable", 0x4C);
    field!(sb, ptr32(), "lpExternalTable", 0x50);
    field!(sb, ptr32(), "lpComRegisterData", 0x54);
    field!(sb, u32_ty(), "bSZProjectDescription", 0x58);
    field!(sb, u32_ty(), "bSZProjectExeName", 0x5C);
    field!(sb, u32_ty(), "bSZProjectHelpFile", 0x60);
    field!(sb, u32_ty(), "bSZProjectName", 0x64);
    build_and_register(bv, "VB6_VbHeader", &mut sb);
}

/// `ProjectData` — 0x23C bytes.
fn define_project_data_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "dwVersion", 0x00);
    field!(sb, ptr32(), "lpObjectTable", 0x04);
    field!(sb, u32_ty(), "null_08", 0x08);
    field!(sb, ptr32(), "lpCodeStart", 0x0C);
    field!(sb, ptr32(), "lpCodeEnd", 0x10);
    field!(sb, u32_ty(), "dwDataSize", 0x14);
    field!(sb, ptr32(), "lpThreadSpace", 0x18);
    field!(sb, ptr32(), "lpVbaSeh", 0x1C);
    field!(sb, ptr32(), "lpNativeCode", 0x20);
    field!(sb, char_array(528), "szPathInfo", 0x24);
    field!(sb, ptr32(), "lpExternalTable", 0x234);
    field!(sb, u32_ty(), "dwExternalCount", 0x238);
    build_and_register(bv, "VB6_ProjectData", &mut sb);
}

/// `ObjectTable` — 0x54 bytes.
fn define_object_table_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "lpHeapLink", 0x00);
    field!(sb, ptr32(), "lpExecProj", 0x04);
    field!(sb, ptr32(), "lpProjectInfo2", 0x08);
    field!(sb, u32_ty(), "reserved_0c", 0x0C);
    field!(sb, u32_ty(), "reserved_10", 0x10);
    field!(sb, ptr32(), "lpProjectObject", 0x14);
    field!(sb, u8_array(16), "uuidObject", 0x18);
    field!(sb, u16_ty(), "fCompileState", 0x28);
    field!(sb, u16_ty(), "wTotalObjects", 0x2A);
    field!(sb, u16_ty(), "wCompiledObjects", 0x2C);
    field!(sb, u16_ty(), "wObjectsInUse", 0x2E);
    field!(sb, ptr32(), "lpObjectArray", 0x30);
    field!(sb, u32_ty(), "ide_flag", 0x34);
    field!(sb, u32_ty(), "ide_data", 0x38);
    field!(sb, u32_ty(), "ide_data_2", 0x3C);
    field!(sb, ptr32(), "lpszProjectName", 0x40);
    field!(sb, u32_ty(), "dwLcid", 0x44);
    field!(sb, u32_ty(), "dwLcid2", 0x48);
    field!(sb, u32_ty(), "ide_data_3", 0x4C);
    field!(sb, u32_ty(), "dwIdentifier", 0x50);
    build_and_register(bv, "VB6_ObjectTable", &mut sb);
}

/// `PublicObjectDescriptor` — 0x30 bytes.
fn define_public_object_descriptor_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, ptr32(), "lpObjectInfo", 0x00);
    field!(sb, u32_ty(), "reserved_04", 0x04);
    field!(sb, ptr32(), "lpPublicBytes", 0x08);
    field!(sb, ptr32(), "lpStaticBytes", 0x0C);
    field!(sb, ptr32(), "lpModulePublic", 0x10);
    field!(sb, ptr32(), "lpModuleStatic", 0x14);
    field!(sb, ptr32(), "lpszObjectName", 0x18);
    field!(sb, u32_ty(), "dwMethodCount", 0x1C);
    field!(sb, ptr32(), "lpMethodNames", 0x20);
    field!(sb, u32_ty(), "oStaticVars", 0x24);
    field!(sb, u32_ty(), "fObjectType", 0x28);
    field!(sb, u32_ty(), "reserved_2c", 0x2C);
    build_and_register(bv, "VB6_PublicObjectDescriptor", &mut sb);
}

/// `ObjectInfo` — 0x38 bytes.
fn define_object_info_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u16_ty(), "wRefCount", 0x00);
    field!(sb, u16_ty(), "wObjectIndex", 0x02);
    field!(sb, ptr32(), "lpObjectTable", 0x04);
    field!(sb, ptr32(), "lpIdeData", 0x08);
    field!(sb, ptr32(), "lpPrivateObject", 0x0C);
    field!(sb, u32_ty(), "reserved_10", 0x10);
    field!(sb, u32_ty(), "reserved_14", 0x14);
    field!(sb, ptr32(), "lpPublicObject", 0x18);
    field!(sb, ptr32(), "lpObjectData", 0x1C);
    field!(sb, u16_ty(), "wMethodCount", 0x20);
    field!(sb, u16_ty(), "wMethodCountIde", 0x22);
    field!(sb, ptr32(), "lpMethods", 0x24);
    field!(sb, u16_ty(), "wConstantsCount", 0x28);
    field!(sb, u16_ty(), "wMaxConstants", 0x2A);
    field!(sb, u32_ty(), "reserved_2c", 0x2C);
    field!(sb, u32_ty(), "reserved_30", 0x30);
    field!(sb, ptr32(), "lpConstants", 0x34);
    build_and_register(bv, "VB6_ObjectInfo", &mut sb);
}

/// `OptionalObjectInfo` — 0x40 bytes (follows `ObjectInfo`).
fn define_optional_object_info_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "gui_guids_count", 0x00);
    field!(sb, ptr32(), "object_clsid_va", 0x04);
    field!(sb, u32_ty(), "null_08", 0x08);
    field!(sb, ptr32(), "gui_guid_table_va", 0x0C);
    field!(sb, u32_ty(), "default_iid_count", 0x10);
    field!(sb, ptr32(), "events_iid_table_va", 0x14);
    field!(sb, u32_ty(), "events_iid_count", 0x18);
    field!(sb, ptr32(), "default_iid_table_va", 0x1C);
    field!(sb, u32_ty(), "control_count", 0x20);
    field!(sb, ptr32(), "controls_va", 0x24);
    field!(sb, u16_ty(), "method_link_count", 0x28);
    field!(sb, u16_ty(), "pcode_count", 0x2A);
    field!(sb, u16_ty(), "initialize_event_offset", 0x2C);
    field!(sb, u16_ty(), "terminate_event_offset", 0x2E);
    field!(sb, ptr32(), "method_link_table_va", 0x30);
    field!(sb, ptr32(), "basic_class_object_va", 0x34);
    field!(sb, u32_ty(), "null_38", 0x38);
    field!(sb, u32_ty(), "field_3c", 0x3C);
    build_and_register(bv, "VB6_OptionalObjectInfo", &mut sb);
}

/// `PrivateObjectDescriptor` — 0x40 bytes.
fn define_private_object_descriptor_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "unused_00", 0x00);
    field!(sb, ptr32(), "lpObjectInfo", 0x04);
    field!(sb, u32_ty(), "reserved_08", 0x08);
    field!(sb, u32_ty(), "unused_0c", 0x0C);
    field!(sb, u16_ty(), "wFuncCount", 0x10);
    field!(sb, u16_ty(), "wFuncCount2", 0x12);
    field!(sb, u16_ty(), "wVarCount", 0x14);
    field!(sb, u16_ty(), "unused_16", 0x16);
    field!(sb, ptr32(), "lpFuncTypDescs", 0x18);
    field!(sb, u32_ty(), "unused_1c", 0x1C);
    field!(sb, ptr32(), "lpMethodNameTable", 0x20);
    field!(sb, ptr32(), "lpParamNames", 0x24);
    field!(sb, ptr32(), "lpVarStubs", 0x28);
    field!(sb, u8_array(12), "unused_2c", 0x2C);
    field!(sb, u32_ty(), "dwDescSize", 0x38);
    field!(sb, u32_ty(), "dwFlags", 0x3C);
    build_and_register(bv, "VB6_PrivateObjectDescriptor", &mut sb);
}

/// `ProcDscInfo` (RTMI header) — fixed 0x24-byte header.
fn define_proc_dsc_info_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, ptr32(), "lpObjectInfo", 0x00);
    field!(sb, u16_ty(), "wArgSize", 0x04);
    field!(sb, u16_ty(), "wFrameSize", 0x06);
    field!(sb, u16_ty(), "wPCodeBackOffset", 0x08);
    field!(sb, u16_ty(), "wTotalSize", 0x0A);
    field!(sb, u16_ty(), "wProcOptFlags", 0x0C);
    field!(sb, u16_ty(), "reserved_0e", 0x0E);
    field!(sb, u16_ty(), "wBosSkipTableOffset", 0x10);
    field!(sb, u16_ty(), "base_iface_slot_count", 0x12);
    field!(sb, u16_ty(), "reserved_14", 0x14);
    field!(sb, u16_ty(), "reserved_16", 0x16);
    field!(sb, u16_ty(), "wCleanupTableSize", 0x18);
    field!(sb, u16_ty(), "reserved_1a", 0x1A);
    field!(sb, u16_ty(), "wCleanupCount", 0x1C);
    field!(sb, u16_ty(), "wCleanupTotal", 0x1E);
    field!(sb, u32_ty(), "flags_padding", 0x20);
    build_and_register(bv, "VB6_ProcDscInfo", &mut sb);
}

/// `ControlInfo` — 0x28 bytes.
fn define_control_info_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u16_ty(), "wFlags", 0x00);
    field!(sb, u16_ty(), "wEventHandlerSlots", 0x02);
    field!(sb, u16_ty(), "wDispatchOffset", 0x04);
    field!(sb, u16_ty(), "reserved_06", 0x06);
    field!(sb, ptr32(), "lpGuid", 0x08);
    field!(sb, u16_ty(), "wIndex", 0x0C);
    field!(sb, u16_ty(), "wMemberType", 0x0E);
    field!(sb, u32_ty(), "wDispIdCount_or_zero", 0x10);
    field!(sb, ptr32(), "lpDispIdTable", 0x14);
    field!(sb, ptr32(), "lpEventSinkVtable", 0x18);
    field!(sb, ptr32(), "lpLinkerTypeData", 0x1C);
    field!(sb, ptr32(), "lpName", 0x20);
    field!(sb, u32_ty(), "dwControlId", 0x24);
    build_and_register(bv, "VB6_ControlInfo", &mut sb);
}

/// `GuiTableEntry` — 0x50 bytes per form/UserControl/MDIForm.
///
/// Pointed to by `VbHeader.lpGuiTable`. One entry per visual object.
fn define_gui_table_entry_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "dwEntrySize", 0x00);
    field!(sb, u8_array(16), "uuidObject", 0x04);
    field!(sb, u8_array(16), "uuidSecondary", 0x14);
    field!(sb, u32_ty(), "dwField24", 0x24);
    field!(sb, u32_ty(), "dwObjectType", 0x28);
    field!(sb, u32_ty(), "dwTypeDataDword", 0x2C);
    field!(sb, u8_array(16), "guidTypeDataIID", 0x30);
    field!(sb, u32_ty(), "dwFormDataSize", 0x40);
    field!(sb, u32_ty(), "reserved_44", 0x44);
    field!(sb, ptr32(), "lpFormData", 0x48);
    field!(sb, u32_ty(), "dwFormDataSize2", 0x4C);
    build_and_register(bv, "VB6_GuiTableEntry", &mut sb);
}

/// `ComRegData` — 0x2A byte header for COM TypeLib registration.
///
/// Pointed to by `VbHeader.lpComRegisterData`. Contains project GUID,
/// version, and linked list of per-object COM registration records.
fn define_com_reg_data_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "bFirstObject", 0x00);
    field!(sb, u32_ty(), "bszProjectName", 0x04);
    field!(sb, u32_ty(), "bszHelpDir", 0x08);
    field!(sb, u32_ty(), "bszDescription", 0x0C);
    field!(sb, u8_array(16), "uuidProject", 0x10);
    field!(sb, u32_ty(), "dwLcid", 0x20);
    field!(sb, u16_ty(), "wRegFlags", 0x24);
    field!(sb, u16_ty(), "wMajorVer", 0x26);
    field!(sb, u16_ty(), "wMinorVer", 0x28);
    build_and_register(bv, "VB6_ComRegData", &mut sb);
}

/// `ComRegObject` — 0x40 byte per-object COM registration record.
///
/// Forms a linked list via self-relative offsets from `ComRegData`.
/// Each record describes one COM-creatable class with its CLSID,
/// ProgID components, interface GUIDs, and registry flags.
///
/// The runtime reads all fields through +0x3E. For non-ActiveX objects,
/// `dwMiscStatus` at +0x34 may contain residual string data from the
/// linker but the struct size is fixed.
fn define_com_reg_object_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "bNextObject", 0x00);
    field!(sb, u32_ty(), "bszObjectName", 0x04);
    field!(sb, u32_ty(), "bszDescription", 0x08);
    field!(sb, u32_ty(), "dwRegFlag", 0x0C);
    field!(sb, u32_ty(), "reserved_10", 0x10);
    field!(sb, u8_array(16), "uuidObject", 0x14);
    field!(sb, u32_ty(), "dwDefaultIfaceCount", 0x24);
    field!(sb, u32_ty(), "bDefaultIfaceGuids", 0x28);
    field!(sb, u32_ty(), "bSourceIfaceGuids", 0x2C);
    field!(sb, u32_ty(), "dwSourceIfaceCount", 0x30);
    field!(sb, u32_ty(), "dwMiscStatus", 0x34);
    field!(sb, u16_ty(), "wObjectFlags", 0x38);
    field!(sb, u16_ty(), "wToolboxBitmap32", 0x3A);
    field!(sb, u16_ty(), "wDefaultIcon", 0x3C);
    field!(sb, u16_ty(), "wExtendedFlags", 0x3E);
    build_and_register(bv, "VB6_ComRegObject", &mut sb);
}

/// `ProjectInfo2` — 0x28 byte header for COM dispatch interface metadata.
///
/// Pointed to by `ObjectTable.lpProjectInfo2`.
fn define_project_info2_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "reserved_00", 0x00);
    field!(sb, ptr32(), "lpObjectTable", 0x04);
    field!(sb, u32_ty(), "reserved_08", 0x08);
    field!(sb, u32_ty(), "reserved_0c", 0x0C);
    field!(sb, ptr32(), "lpObjectDescs", 0x10);
    field!(sb, u8_array(12), "reserved_14", 0x14);
    field!(sb, u32_ty(), "reserved_20", 0x20);
    field!(sb, u32_ty(), "reserved_24", 0x24);
    build_and_register(bv, "VB6_ProjectInfo2", &mut sb);
}

/// `FuncTypDesc` — 0x14 bytes (20 bytes meaningful) per function prototype.
///
/// Accessed via `PrivateObjectDescriptor.lpFuncTypDescs` pointer array.
fn define_func_typ_desc_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u8_ty(), "bArgSize", 0x00);
    field!(sb, u8_ty(), "bFlags", 0x01);
    field!(sb, u16_ty(), "wVTableOffset", 0x02);
    field!(sb, u16_ty(), "iObjectIndex", 0x04);
    field!(sb, u16_ty(), "reserved_06", 0x06);
    field!(sb, ptr32(), "lpOptionalDefaults", 0x08);
    field!(sb, u16_ty(), "wNameIndex", 0x0C);
    field!(sb, u8_ty(), "bReturnType", 0x0E);
    field!(sb, u8_ty(), "bFuncFlags", 0x0F);
    field!(sb, ptr32(), "lpParamNames", 0x10);
    build_and_register(bv, "VB6_FuncTypDesc", &mut sb);
}

/// `ExternalDeclareInfo` — 0x10 bytes per `Declare Function` import.
///
/// Pointed to by `ExternalTableEntry.lpExternalObject` when
/// `fExternalType == 0x07`.
fn define_external_declare_info_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, ptr32(), "lpLibraryName", 0x00);
    field!(sb, ptr32(), "lpFunctionName", 0x04);
    field!(sb, u32_ty(), "dwFlags", 0x08);
    field!(sb, ptr32(), "lpNativeStub", 0x0C);
    build_and_register(bv, "VB6_ExternalDeclareInfo", &mut sb);
}

/// `ExternalTypelibInfo` — 0x08 bytes per COM typelib reference.
///
/// Pointed to by `ExternalTableEntry.lpExternalObject` when
/// `fExternalType == 0x06`.
fn define_external_typelib_info_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, ptr32(), "lpTypelibGuid", 0x00);
    field!(sb, ptr32(), "lpRuntimeData", 0x04);
    build_and_register(bv, "VB6_ExternalTypelibInfo", &mut sb);
}

/// `CleanupTableHeader` — 0x0C-byte header for cleanup/property tables.
///
/// Used by both the primary cleanup table (ProcDscInfo +0x18, processed
/// by runtime) and the secondary table (immediately following, purpose
/// unknown). Variable-length entries follow this header.
fn define_cleanup_table_header_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u16_ty(), "wSize", 0x00);
    field!(sb, u16_ty(), "reserved", 0x02);
    field!(sb, u16_ty(), "wCount", 0x04);
    field!(sb, u16_ty(), "wTotal", 0x06);
    field!(sb, u32_ty(), "flags", 0x08);
    build_and_register(bv, "VB6_CleanupTableHeader", &mut sb);
}

/// `VARIANT` — 16-byte COM variant type (OLE Automation).
///
/// Used by MSVBVM60 runtime functions for variant parameters. The `vt`
/// field (VARTYPE) determines interpretation of the 8-byte data union.
fn define_variant_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u16_ty(), "vt", 0x00);
    field!(sb, u16_ty(), "wReserved1", 0x02);
    field!(sb, u16_ty(), "wReserved2", 0x04);
    field!(sb, u16_ty(), "wReserved3", 0x06);
    field!(sb, u8_array(8), "data", 0x08);
    build_and_register(bv, "VARIANT", &mut sb);
}

/// `GUID` — 16-byte COM globally unique identifier.
fn define_guid_struct_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u32_ty(), "Data1", 0x00);
    field!(sb, u16_ty(), "Data2", 0x04);
    field!(sb, u16_ty(), "Data3", 0x06);
    field!(sb, u8_array(8), "Data4", 0x08);
    build_and_register(bv, "GUID", &mut sb);
}

/// `FormDataHeader` — 0x61-byte header of form binary data.
///
/// Pointed to by `GuiTableEntry.lpFormData`. Contains form dimensions
/// and three GUIDs identifying the form and its control type.
fn define_form_data_header_type(bv: &BinaryView) {
    let mut sb = StructureBuilder::new();
    field!(sb, u16_ty(), "wMagic", 0x00);
    field!(sb, u16_ty(), "wVersion", 0x02);
    field!(sb, u8_ty(), "bSiteFlags", 0x04);
    field!(sb, u8_array(16), "uuidFormGuid", 0x05);
    field!(sb, u8_array(16), "uuidSecondaryGuid", 0x15);
    field!(sb, u8_array(16), "uuidDefaultControlGuid", 0x25);
    field!(sb, u8_array(36), "reserved", 0x35);
    field!(sb, u32_ty(), "dwWidth", 0x59);
    field!(sb, u32_ty(), "dwHeight", 0x5D);
    build_and_register(bv, "VB6_FormDataHeader", &mut sb);
}
