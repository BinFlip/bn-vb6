//! VB6 P-Code custom architecture for Binary Ninja.
//!
//! Registers `VB6-PCode` as a Binary Ninja architecture and `vb6-pcode` as its
//! platform, enabling P-Code regions to be disassembled into readable VB6
//! mnemonics with proper control flow (branches, returns) and LLIL lifting.
//!
//! # Architecture callbacks
//!
//! Binary Ninja calls three methods per instruction:
//!
//! - [`instruction_info`] — Returns instruction length and branch targets for
//!   CFG construction.
//! - [`instruction_text`] — Returns tokenized disassembly text (mnemonic +
//!   operands) with resolved names for `%x`, `%s`, `%v`, and `%a` operands.
//! - [`instruction_llil`] — Emits LLIL via [`crate::lift::lift_instruction`].
//!
//! All three clamp the byte slice to the method boundary to prevent decoding
//! past the P-Code byte stream into the trailing `ProcDscInfo` structure.
//!
//! # Global state
//!
//! Five global maps (populated during annotation, read during arch callbacks):
//!
//! - **P-Code functions** — `base_va -> PCodeFunctionMeta` for method boundary
//!   detection, jump target resolution, and per-function context.
//! - **Import targets** — `import_index -> symbol_va` for `ImpAdCall` LLIL.
//! - **Import names** — `import_index -> "library!function"` for `%x` display.
//! - **Const strings** — `(data_const_va, offset) -> string` for `%s` display.
//! - **Control names** — `(object_index, control_index) -> name` for `%v` display.
//!
//! [`instruction_info`]: Vb6PCodeArch::instruction_info
//! [`instruction_text`]: Vb6PCodeArch::instruction_text
//! [`instruction_llil`]: Vb6PCodeArch::instruction_llil

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::RwLock;

use binaryninja::Endianness;
use binaryninja::architecture::*;
use binaryninja::disassembly::{InstructionTextToken, InstructionTextTokenKind};
use binaryninja::low_level_il::LowLevelILMutableFunction;
use visualbasic::pcode::opcode::{self, OpcodeInfo};
use visualbasic::pcode::operand::{self, Operand};
use visualbasic::vb::procedure::pcode_frame;

/// Metadata for a registered P-Code function.
///
/// Stored in [`PCODE_FUNCTIONS`] during annotation and looked up during
/// architecture callbacks to determine method boundaries, resolve jump
/// targets (relative to function base), and provide context for operand
/// name resolution.
pub struct PCodeFunctionMeta {
    /// Length of the P-Code byte stream in bytes.
    pub pcode_size: u16,
    /// Constant pool base VA for this method's string/import references.
    pub data_const_va: u64,
    /// Index of the parent VB6 object (for `%v` control name resolution).
    pub object_index: u16,
}

static PCODE_FUNCTIONS: RwLock<BTreeMap<u64, PCodeFunctionMeta>> = RwLock::new(BTreeMap::new());
static IMPORT_TARGETS: RwLock<BTreeMap<u16, u64>> = RwLock::new(BTreeMap::new());
static IMPORT_NAMES: RwLock<BTreeMap<u16, String>> = RwLock::new(BTreeMap::new());
static CONST_STRINGS: RwLock<BTreeMap<(u64, u16), String>> = RwLock::new(BTreeMap::new());
static CONTROL_NAMES: RwLock<BTreeMap<(u16, u16), String>> = RwLock::new(BTreeMap::new());

/// Register a P-Code function's metadata for architecture callbacks.
pub fn register_pcode_function(base_va: u64, meta: PCodeFunctionMeta) {
    if let Ok(mut map) = PCODE_FUNCTIONS.write() {
        map.insert(base_va, meta);
    }
}

/// Register a resolved import target VA for LLIL lifting.
pub fn register_import_target(import_index: u16, va: u64) {
    if let Ok(mut map) = IMPORT_TARGETS.write() {
        map.insert(import_index, va);
    }
}

/// Register a resolved import name for `instruction_text` `%x` display.
pub fn register_import_name(import_index: u16, name: String) {
    if let Ok(mut map) = IMPORT_NAMES.write() {
        map.insert(import_index, name);
    }
}

/// Register a resolved constant pool string for `instruction_text` `%s` display.
pub fn register_const_string(data_const_va: u64, offset: u16, s: String) {
    if let Ok(mut map) = CONST_STRINGS.write() {
        map.insert((data_const_va, offset), s);
    }
}

/// Register a control name for `instruction_text` `%v` display.
pub fn register_control_name(object_index: u16, control_index: u16, name: String) {
    if let Ok(mut map) = CONTROL_NAMES.write() {
        map.insert((object_index, control_index), name);
    }
}

/// Clear all global state maps (called before re-analysis).
pub fn clear_all() {
    if let Ok(mut m) = PCODE_FUNCTIONS.write() {
        m.clear();
    }
    if let Ok(mut m) = IMPORT_TARGETS.write() {
        m.clear();
    }
    if let Ok(mut m) = IMPORT_NAMES.write() {
        m.clear();
    }
    if let Ok(mut m) = CONST_STRINGS.write() {
        m.clear();
    }
    if let Ok(mut m) = CONTROL_NAMES.write() {
        m.clear();
    }
}

/// Look up a resolved import target VA for LLIL lifting.
pub fn lookup_import_target(import_index: u16) -> Option<u64> {
    IMPORT_TARGETS.read().ok()?.get(&import_index).copied()
}

/// Look up the P-Code function containing `addr`.
///
/// Returns `(base_va, pcode_size, data_const_va, object_index)`.
fn lookup_function_meta(addr: u64) -> Option<(u64, u16, u64, u16)> {
    let map = PCODE_FUNCTIONS.read().ok()?;
    map.range(..=addr)
        .next_back()
        .filter(|(base, meta)| addr < **base + meta.pcode_size as u64)
        .map(|(base, meta)| {
            (
                *base,
                meta.pcode_size,
                meta.data_const_va,
                meta.object_index,
            )
        })
}

fn lookup_function(addr: u64) -> Option<u64> {
    lookup_function_meta(addr).map(|(base, _, _, _)| base)
}

fn lookup_import_name(import_index: u16) -> Option<String> {
    IMPORT_NAMES.read().ok()?.get(&import_index).cloned()
}

fn lookup_const_string(data_const_va: u64, offset: u16) -> Option<String> {
    CONST_STRINGS
        .read()
        .ok()?
        .get(&(data_const_va, offset))
        .cloned()
}

fn lookup_control_name(object_index: u16, control_index: u16) -> Option<String> {
    CONTROL_NAMES
        .read()
        .ok()?
        .get(&(object_index, control_index))
        .cloned()
}

/// Returns `true` if `addr` is past the end of its containing P-Code method.
fn is_past_method_end(addr: u64) -> bool {
    let map = PCODE_FUNCTIONS.read().ok();
    let Some(map) = map.as_ref() else {
        return false;
    };
    match map.range(..=addr).next_back() {
        Some((base, meta)) => addr >= *base + meta.pcode_size as u64,
        None => true,
    }
}

/// Clamp `data` to the method boundary so we don't decode past `ProcDscInfo`.
fn clamp_to_method(data: &[u8], addr: u64) -> Option<&[u8]> {
    if is_past_method_end(addr) {
        return None;
    }
    let data = if let Some((base, size, _, _)) = lookup_function_meta(addr) {
        let remaining = (base + size as u64).saturating_sub(addr) as usize;
        &data[..data.len().min(remaining)]
    } else {
        data
    };
    if data.is_empty() { None } else { Some(data) }
}

/// The single register in the P-Code stack-machine model.
///
/// P-Code uses an implicit evaluation stack, but we expose EBP as a named
/// register for frame-relative variable access in the LLIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PCodeReg {
    Ebp,
}

impl Register for PCodeReg {
    type InfoType = PCodeRegInfo;
    fn name(&self) -> Cow<'_, str> {
        "ebp".into()
    }
    fn info(&self) -> PCodeRegInfo {
        PCodeRegInfo(*self)
    }
    fn id(&self) -> RegisterId {
        RegisterId(0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PCodeRegInfo(PCodeReg);

impl RegisterInfo for PCodeRegInfo {
    type RegType = PCodeReg;
    fn parent(&self) -> Option<PCodeReg> {
        None
    }
    fn size(&self) -> usize {
        4
    }
    fn offset(&self) -> usize {
        0
    }
    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        ImplicitRegisterExtend::NoExtend
    }
}

// ── Architecture implementation ─────────────────────────────────────────────

/// The VB6 P-Code architecture implementation.
///
/// Registered as `"VB6-PCode"` with a 32-bit little-endian address space and
/// variable-length instructions (1-256 bytes).
pub struct Vb6PCodeArch {
    handle: CustomArchitectureHandle<Self>,
    core: CoreArchitecture,
}

impl AsRef<CoreArchitecture> for Vb6PCodeArch {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.core
    }
}

impl Architecture for Vb6PCodeArch {
    type Handle = CustomArchitectureHandle<Self>;
    type RegisterInfo = PCodeRegInfo;
    type Register = PCodeReg;
    type RegisterStack = UnusedRegisterStack<PCodeReg>;
    type RegisterStackInfo = UnusedRegisterStack<PCodeReg>;
    type Flag = UnusedFlag;
    type FlagWrite = UnusedFlag;
    type FlagClass = UnusedFlag;
    type FlagGroup = UnusedFlag;
    type Intrinsic = UnusedIntrinsic;

    fn handle(&self) -> CustomArchitectureHandle<Self> {
        self.handle
    }
    fn endianness(&self) -> Endianness {
        Endianness::LittleEndian
    }
    fn address_size(&self) -> usize {
        4
    }
    fn default_integer_size(&self) -> usize {
        2
    }
    fn instruction_alignment(&self) -> usize {
        1
    }
    fn max_instr_len(&self) -> usize {
        256
    }
    fn opcode_display_len(&self) -> usize {
        6
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        let data = clamp_to_method(data, addr)?;
        let (info, len) = decode_instruction(data)?;

        let mut result = InstructionInfo::new(len, 0);
        let mnemonic = info.mnemonic;

        if mnemonic == "Branch" {
            if let Some(target) = extract_jump_target(data, info, addr) {
                result.add_branch(BranchKind::Unconditional(target));
            }
        } else if mnemonic.starts_with("BranchF") || mnemonic.starts_with("BranchT") {
            if let Some(target) = extract_jump_target(data, info, addr) {
                result.add_branch(BranchKind::True(target));
                result.add_branch(BranchKind::False(addr + len as u64));
            }
        } else if mnemonic.starts_with("ExitProc")
            || mnemonic == "End"
            || mnemonic == "Return"
            || mnemonic == "Ret"
        {
            result.add_branch(BranchKind::FunctionReturn);
        }

        Some(result)
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        let data = clamp_to_method(data, addr)?;
        let (info, len) = decode_instruction(data)?;

        let mut tokens = Vec::new();
        tokens.push(InstructionTextToken::new(
            info.mnemonic,
            InstructionTextTokenKind::Instruction,
        ));

        let opcode_bytes = if info.is_lead_byte() { 2 } else { 1 };
        let operands = decode_operands(data, info, opcode_bytes);

        if !operands.is_empty() {
            let pad_len = 16usize.saturating_sub(info.mnemonic.len());
            tokens.push(InstructionTextToken::new(
                " ".repeat(pad_len),
                InstructionTextTokenKind::Text,
            ));
        }

        let func_meta = lookup_function_meta(addr);
        let func_base = func_meta.map(|(base, _, _, _)| base);

        for (i, op) in operands.iter().enumerate() {
            if i > 0 {
                tokens.push(InstructionTextToken::new(
                    ", ",
                    InstructionTextTokenKind::OperandSeparator,
                ));
            }
            match op {
                Operand::StackVar(offset) => {
                    tokens.push(InstructionTextToken::new(
                        format_stack_var(*offset),
                        InstructionTextTokenKind::Text,
                    ));
                }
                Operand::JumpTarget(target) => {
                    let abs_target = func_base
                        .map(|base| base + *target as u64)
                        .unwrap_or(*target as u64);
                    tokens.push(InstructionTextToken::new(
                        format!("0x{abs_target:08x}"),
                        InstructionTextTokenKind::CodeRelativeAddress {
                            value: abs_target,
                            size: Some(4),
                        },
                    ));
                }
                Operand::ConstPoolIndex(idx) => {
                    let text = func_meta
                        .and_then(|(_, _, dcv, _)| lookup_const_string(dcv, *idx))
                        .map(|s| {
                            if s.len() > 40 {
                                format!("\"{}...\"", &s[..37])
                            } else {
                                format!("\"{s}\"")
                            }
                        })
                        .unwrap_or_else(|| format!("[const+0x{idx:04X}]"));
                    tokens.push(InstructionTextToken::new(
                        text,
                        InstructionTextTokenKind::Text,
                    ));
                }
                Operand::Byte(v) => {
                    tokens.push(InstructionTextToken::new(
                        format!("0x{v:02X}"),
                        InstructionTextTokenKind::Integer {
                            value: *v as u64,
                            size: Some(1),
                        },
                    ));
                }
                Operand::Int16(v) => {
                    tokens.push(InstructionTextToken::new(
                        format!("0x{:04X}", *v as u16),
                        InstructionTextTokenKind::Integer {
                            value: *v as u64,
                            size: Some(2),
                        },
                    ));
                }
                Operand::Int32(v) => {
                    tokens.push(InstructionTextToken::new(
                        format!("0x{:08X}", *v as u32),
                        InstructionTextTokenKind::Integer {
                            value: *v as u64,
                            size: Some(4),
                        },
                    ));
                }
                Operand::ControlIndex(idx) => {
                    tokens.push(InstructionTextToken::new(
                        format!("ctrl[{idx}]"),
                        InstructionTextTokenKind::Text,
                    ));
                }
                Operand::VTableRef { offset, control } => {
                    let text = func_meta
                        .and_then(|(_, _, _, obj_idx)| lookup_control_name(obj_idx, *control))
                        .map(|name| format!("{name}.vtbl+0x{offset:X}"))
                        .unwrap_or_else(|| format!("vtbl[{control}+0x{offset:X}]"));
                    tokens.push(InstructionTextToken::new(
                        text,
                        InstructionTextTokenKind::Text,
                    ));
                }
                Operand::ExternalCall { import, arg_info } => {
                    let text = lookup_import_name(*import)
                        .map(|name| format!("{name}(0x{arg_info:04X})"))
                        .unwrap_or_else(|| format!("ext[{import}](0x{arg_info:04X})"));
                    tokens.push(InstructionTextToken::new(
                        text,
                        InstructionTextTokenKind::Text,
                    ));
                }
                Operand::VariableLength { byte_count } => {
                    tokens.push(InstructionTextToken::new(
                        format!("({byte_count} bytes)"),
                        InstructionTextTokenKind::Text,
                    ));
                }
            }
        }

        Some((len, tokens))
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &LowLevelILMutableFunction,
    ) -> Option<(usize, bool)> {
        let data = clamp_to_method(data, addr)?;
        let (info, len) = decode_instruction(data)?;

        let opcode_bytes = if info.is_lead_byte() { 2 } else { 1 };
        let operands = if info.is_variable_length() {
            if data.len() >= opcode_bytes + 2 {
                let bc = u16::from_le_bytes([data[opcode_bytes], data[opcode_bytes + 1]]);
                [
                    Some(Operand::VariableLength { byte_count: bc }),
                    None,
                    None,
                    None,
                ]
            } else {
                [None; 4]
            }
        } else {
            let mut pos = opcode_bytes;
            operand::decode_operands(info.operand_format, data, &mut pos, data.len())
                .unwrap_or([None; 4])
        };

        let func_base = lookup_function(addr);
        let lifted = crate::lift::lift_instruction(il, info, &operands, addr, len, func_base);
        Some((len, lifted))
    }

    fn registers_all(&self) -> Vec<PCodeReg> {
        vec![PCodeReg::Ebp]
    }
    fn registers_full_width(&self) -> Vec<PCodeReg> {
        vec![PCodeReg::Ebp]
    }

    fn register_from_id(&self, id: RegisterId) -> Option<PCodeReg> {
        match id.0 {
            0 => Some(PCodeReg::Ebp),
            _ => None,
        }
    }

    fn stack_pointer_reg(&self) -> Option<PCodeReg> {
        Some(PCodeReg::Ebp)
    }
}

/// Register the `VB6-PCode` architecture and `vb6-pcode` platform with BN.
pub fn register() {
    let arch = register_architecture("VB6-PCode", |handle, core| Vb6PCodeArch { handle, core });
    let platform = binaryninja::platform::Platform::new(arch, "vb6-pcode");
    platform.register_os("VB6");
}

// ── Stack variable formatting ───────────────────────────────────────────────

/// Format a `%a` stack variable offset as a human-readable name.
///
/// Uses the P-Code frame layout constants from [`pcode_frame`]:
/// - `offset >= 8`: argument (`arg_0`, `arg_1`, ...)
/// - `offset == 4`: return address
/// - `offset == 0`: saved EBP
/// - `-0x88 <= offset < 0`: housekeeping slot (named or generic)
/// - `offset < -0x88`: local variable (`local_0`, `local_1`, ...)
fn format_stack_var(offset: i16) -> String {
    if offset >= 8 {
        return format!("arg_{}", (offset as u16 - 8) / 4);
    }
    if offset >= 0 {
        return if offset == 4 {
            "ret_addr".into()
        } else {
            "saved_ebp".into()
        };
    }

    let abs_offset = (-(offset as i32)) as u32;
    if abs_offset <= pcode_frame::HOUSEKEEPING_SIZE {
        let name = match offset as i32 {
            pcode_frame::PCODE_IP => "pcode_ip",
            pcode_frame::CONST_POOL_VA => "const_pool",
            pcode_frame::PROC_DSC_INFO => "proc_dsc",
            pcode_frame::ERROR_HANDLER_IP => "err_handler",
            pcode_frame::ERROR_TARGET => "err_target",
            pcode_frame::ENGINE_CONTEXT => "engine_ctx",
            pcode_frame::ENGINE_TLS => "engine_tls",
            pcode_frame::PROC_FLAGS => "proc_flags",
            pcode_frame::OBJECT_PTR => "this",
            pcode_frame::ERROR_STATE => "err_state",
            pcode_frame::SAVED_PCODE_IP => "saved_ip",
            pcode_frame::HANDLER_FN => "handler_fn",
            _ => return format!("hk_{:X}", abs_offset),
        };
        return name.into();
    }

    format!(
        "local_{}",
        (abs_offset - pcode_frame::HOUSEKEEPING_SIZE) / 4
    )
}

// ── Instruction decoding ────────────────────────────────────────────────────

/// Decode one P-Code instruction from raw bytes.
///
/// Handles both primary (1-byte) and extended (2-byte lead prefix) opcodes.
/// Returns `(opcode_info, total_length)`.
fn decode_instruction(data: &[u8]) -> Option<(&'static OpcodeInfo, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    let table = opcode::table_by_index(opcode::DispatchTable::Primary);
    let primary = &table[first_byte as usize];

    if primary.is_lead_byte() {
        let next = data.get(1).copied()?;
        let ext_table = match first_byte {
            0xFB => opcode::table_by_index(opcode::DispatchTable::Lead0),
            0xFC => opcode::table_by_index(opcode::DispatchTable::Lead1),
            0xFD => opcode::table_by_index(opcode::DispatchTable::Lead2),
            0xFE => opcode::table_by_index(opcode::DispatchTable::Lead3),
            0xFF => opcode::table_by_index(opcode::DispatchTable::Lead4),
            _ => return None,
        };
        let info = &ext_table[next as usize];
        Some((info, compute_instruction_length(info, data, 2)))
    } else {
        Some((primary, compute_instruction_length(primary, data, 1)))
    }
}

/// Compute total instruction length from [`OpcodeInfo`] and raw bytes.
fn compute_instruction_length(info: &OpcodeInfo, data: &[u8], opcode_bytes: usize) -> usize {
    if info.is_variable_length() {
        if data.len() < opcode_bytes + 2 {
            return opcode_bytes;
        }
        let byte_count = u16::from_le_bytes([data[opcode_bytes], data[opcode_bytes + 1]]) as usize;
        opcode_bytes + 2 + byte_count
    } else if info.size > 0 {
        (opcode_bytes - 1) + info.size as usize
    } else {
        opcode_bytes
    }
}

/// Extract the `%l` (jump target) operand as an absolute VA.
fn extract_jump_target(data: &[u8], info: &OpcodeInfo, addr: u64) -> Option<u64> {
    let opcode_bytes = if info.is_lead_byte() { 2 } else { 1 };
    let mut pos = opcode_bytes;
    for spec in info.operand_format.split_whitespace() {
        match spec {
            "%l" => {
                if data.len() < pos + 2 {
                    return None;
                }
                let target_offset = u16::from_le_bytes([data[pos], data[pos + 1]]);
                let func_base = lookup_function(addr)?;
                return Some(func_base + target_offset as u64);
            }
            "%a" | "%s" | "%c" | "%2" => pos += 2,
            "%v" | "%x" | "%4" => pos += 4,
            "%1" => pos += 1,
            _ => {}
        }
    }
    None
}

/// Decode all operands from raw instruction bytes using the format string.
fn decode_operands(data: &[u8], info: &OpcodeInfo, opcode_bytes: usize) -> Vec<Operand> {
    if info.is_variable_length() {
        if data.len() >= opcode_bytes + 2 {
            let byte_count = u16::from_le_bytes([data[opcode_bytes], data[opcode_bytes + 1]]);
            return vec![Operand::VariableLength { byte_count }];
        }
        return vec![];
    }

    let mut pos = opcode_bytes;
    match operand::decode_operands(info.operand_format, data, &mut pos, data.len()) {
        Ok(ops) => ops.into_iter().flatten().collect(),
        Err(_) => vec![],
    }
}
