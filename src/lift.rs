//! LLIL lifting for VB6 P-Code instructions.
//!
//! The VB6 P-Code VM has two stacks:
//!
//! - **Evaluation stack** — 4-byte slots for integer/pointer values.
//! - **FPU stack** — x87-style stack for `Single`/`Double` float operations.
//!
//! We model both using LLIL temp registers. Each basic block starts with a
//! fresh stack state; continuity is tracked by address adjacency (if the
//! current instruction immediately follows the previous one, stacks are
//! preserved).
//!
//! # Semantic dispatch
//!
//! Each P-Code opcode has an [`OpcodeSemantics`] classification from the
//! `visualbasic` crate. The core emission logic dispatches on this to
//! produce the correct LLIL:
//!
//! - **Load/Store** — Frame-relative (`ebp+offset`), member access
//!   (`obj->field`), indirect (`*ptr`), array indexing.
//! - **Arithmetic/Unary/Compare** — Integer and FPU variants, including
//!   in-place FPU modifications (`FnIntR8`, `FnFixR8`).
//! - **Branch** — Conditional (`BranchT`/`BranchF`) and unconditional
//!   (`Branch`), with targets resolved relative to the function base.
//! - **Call** — COM vtable calls (`VCall`/`ThisVCall`), import calls
//!   (`ImpAdCall` resolved via [`crate::arch::lookup_import_target`]),
//!   and late-bound `IDispatch` calls.
//! - **Convert** — Type conversions between integer and FPU representations.
//! - **Stack/IO** — Runtime calls (e.g., `GetLastError`) emitted as
//!   `call(0)` with placeholder return values.

use std::cell::RefCell;

use binaryninja::low_level_il::{LowLevelILMutableFunction, LowLevelILTempRegister};
use visualbasic::pcode::{
    opcode::OpcodeInfo,
    operand::Operand,
    semantics::{ArithOp, CallKind, LoadSource, OpcodeSemantics, StoreTarget},
};

/// Temp register ID reserved for the EBP frame pointer.
const EBP_TEMP: u32 = 0x7FFE;

/// EBP offset to the `this` object pointer in the VB6 runtime stack frame.
///
/// The MSVBVM60 `ProcCallEngine` sets up the frame so that `[ebp-0x30]`
/// points to the current object instance.
const OBJECT_PTR_OFFSET: i32 = -0x30;

/// Return the EBP temp register.
fn ebp() -> LowLevelILTempRegister {
    LowLevelILTempRegister::new(EBP_TEMP)
}

/// Dual-stack model tracking the evaluation stack and FPU stack.
///
/// Each stack entry is the ID of an LLIL temp register. Push allocates a new
/// temp and records its ID; pop retrieves the most recent ID (or allocates a
/// fresh one if the tracked stack is empty, which happens at basic block
/// boundaries).
struct StackModel {
    /// Next temp register ID to allocate.
    next_temp: u32,
    /// Evaluation stack (4-byte integer/pointer slots).
    eval: Vec<u32>,
    /// FPU stack (x87-style float slots).
    fpu: Vec<u32>,
}

impl StackModel {
    fn new() -> Self {
        Self {
            next_temp: 0,
            eval: Vec::with_capacity(16),
            fpu: Vec::with_capacity(8),
        }
    }

    /// Clear both stacks (called at basic block boundaries).
    fn reset(&mut self) {
        self.eval.clear();
        self.fpu.clear();
    }

    /// Allocate a fresh temp register.
    fn alloc(&mut self) -> LowLevelILTempRegister {
        let id = self.next_temp;
        self.next_temp += 1;
        LowLevelILTempRegister::new(id)
    }

    fn push_eval(&mut self) -> LowLevelILTempRegister {
        let t = self.alloc();
        self.eval.push(t.id().0 & 0x7FFF_FFFF);
        t
    }

    fn pop_eval(&mut self) -> LowLevelILTempRegister {
        match self.eval.pop() {
            Some(id) => LowLevelILTempRegister::new(id),
            None => self.alloc(),
        }
    }

    fn push_fpu(&mut self) -> LowLevelILTempRegister {
        let t = self.alloc();
        self.fpu.push(t.id().0 & 0x7FFF_FFFF);
        t
    }

    fn pop_fpu(&mut self) -> LowLevelILTempRegister {
        match self.fpu.pop() {
            Some(id) => LowLevelILTempRegister::new(id),
            None => self.alloc(),
        }
    }

    fn pop_eval_n(&mut self, n: u32) {
        for _ in 0..n {
            self.pop_eval();
        }
    }
    fn push_eval_n(&mut self, n: i8) {
        for _ in 0..n.max(0) {
            self.push_eval();
        }
    }
}

/// Per-thread state tracking address continuity across `instruction_llil` calls.
///
/// BN calls `instruction_llil` sequentially within a basic block. We detect
/// continuity by checking if the current address equals `last_addr + last_len`;
/// if not, we reset the stack model for the new basic block.
struct LiftState {
    last_addr: u64,
    last_len: usize,
    stack: StackModel,
}

impl LiftState {
    fn new() -> Self {
        Self {
            last_addr: 0,
            last_len: 0,
            stack: StackModel::new(),
        }
    }
    fn prepare(&mut self, addr: u64) {
        if addr != self.last_addr.wrapping_add(self.last_len as u64) {
            self.stack.reset();
        }
    }
    fn finish(&mut self, addr: u64, len: usize) {
        self.last_addr = addr;
        self.last_len = len;
    }
}

thread_local! {
    static LIFT_STATE: RefCell<LiftState> = RefCell::new(LiftState::new());
}

/// Lift a single P-Code instruction to LLIL.
///
/// Called from [`Vb6PCodeArch::instruction_llil`](crate::arch::Vb6PCodeArch).
/// Returns `true` if the instruction was successfully lifted, `false` if it
/// should be treated as unimplemented.
///
/// # Arguments
///
/// - `il` — The mutable LLIL function to append instructions to.
/// - `info` — Static opcode metadata from the dispatch tables.
/// - `operands` — Up to 4 decoded operands.
/// - `addr` — Virtual address of this instruction.
/// - `len` — Total instruction length in bytes.
/// - `func_base` — Base VA of the containing P-Code function (for jump targets).
pub fn lift_instruction(
    il: &LowLevelILMutableFunction,
    info: &'static OpcodeInfo,
    operands: &[Option<Operand>; 4],
    addr: u64,
    len: usize,
    func_base: Option<u64>,
) -> bool {
    LIFT_STATE.with(|cell| {
        let mut state = cell.borrow_mut();
        state.prepare(addr);
        let result = emit_il(il, info, operands, addr, len, func_base, &mut state.stack);
        state.finish(addr, len);
        result
    })
}

/// Data size in bytes for this opcode's primary data type (defaults to 4).
fn data_size(info: &OpcodeInfo) -> usize {
    info.data_type
        .map(|dt| dt.eval_stack_bytes() as usize)
        .unwrap_or(4)
        .max(1)
}

/// Returns `true` if this opcode touches the FPU stack (push, pop, or in-place).
fn is_fpu_op(info: &OpcodeInfo) -> bool {
    info.fpu_pops > 0 || info.fpu_push > 0 || info.fpu_inplace
}

/// Extract a `%a` (StackVar) frame offset from the first operand.
fn op_frame_offset(operands: &[Option<Operand>; 4]) -> Option<i16> {
    match operands[0] {
        Some(Operand::StackVar(v)) => Some(v),
        _ => None,
    }
}

/// Extract a `%2` (Int16) member offset from any operand position.
fn op_member_offset(operands: &[Option<Operand>; 4]) -> Option<u16> {
    operands.iter().find_map(|o| match o {
        Some(Operand::Int16(v)) => Some(*v as u16),
        _ => None,
    })
}

/// Extract a `%v` (VTableRef) operand as `(vtable_offset, control_index)`.
fn op_vtable(operands: &[Option<Operand>; 4]) -> Option<(u16, u16)> {
    operands.iter().find_map(|o| match o {
        Some(Operand::VTableRef { offset, control }) => Some((*offset, *control)),
        _ => None,
    })
}

/// Extract a `%x` (ExternalCall) operand as `(import_index, arg_info)`.
fn op_external(operands: &[Option<Operand>; 4]) -> Option<(u16, u16)> {
    operands.iter().find_map(|o| match o {
        Some(Operand::ExternalCall { import, arg_info }) => Some((*import, *arg_info)),
        _ => None,
    })
}

/// Derive the call argument count from `%v` or `%x` operands.
///
/// The `arg_info` / `control` field encodes `arg_count * 4`.
fn call_arg_count(operands: &[Option<Operand>; 4]) -> u32 {
    if let Some((_, ctl)) = op_vtable(operands) {
        return (ctl / 4) as u32;
    }
    if let Some((_, ai)) = op_external(operands) {
        return (ai / 4) as u32;
    }
    0
}

/// Parse the comparison kind from a P-Code mnemonic prefix.
///
/// Returns `(is_float, kind)` where kind: 0=eq, 1=ne, 2=gt, 3=ge, 4=lt, 5=le.
fn cmp_kind(m: &str) -> (bool, u8) {
    let f = m.contains("R4") || m.contains("R8");
    let k = if m.starts_with("Ne") {
        1
    } else if m.starts_with("Gt") {
        2
    } else if m.starts_with("Ge") {
        3
    } else if m.starts_with("Lt") {
        4
    } else if m.starts_with("Le") {
        5
    } else {
        0
    };
    (f, k)
}

/// Core IL emission — dispatches on [`OpcodeSemantics`] to produce LLIL.
fn emit_il(
    il: &LowLevelILMutableFunction,
    info: &'static OpcodeInfo,
    operands: &[Option<Operand>; 4],
    addr: u64,
    len: usize,
    func_base: Option<u64>,
    s: &mut StackModel,
) -> bool {
    let sz = data_size(info);
    let fpu = is_fpu_op(info);
    let mn = info.mnemonic;

    match &info.semantics {
        OpcodeSemantics::Nop => {
            il.add_instruction(il.nop());
            true
        }

        OpcodeSemantics::Load { source } => {
            let dest = if fpu { s.push_fpu() } else { s.push_eval() };
            for _ in 1..info.pushes.max(1) {
                s.push_eval();
            }

            match source {
                LoadSource::Literal => {
                    let val = match operands[0] {
                        Some(Operand::Int32(v)) => v as u64,
                        Some(Operand::Int16(v)) => v as i32 as u64,
                        Some(Operand::Byte(v)) => v as u64,
                        Some(Operand::StackVar(v)) => v as i32 as u64,
                        _ => 0,
                    };
                    il.add_instruction(il.set_reg(sz, dest, il.const_int(sz, val)));
                }
                LoadSource::Frame => {
                    if let Some(off) = op_frame_offset(operands) {
                        let a = il.add(4, il.reg(4, ebp()), il.const_int(4, off as i32 as u64));
                        let lsz = if fpu { 4 } else { sz };
                        il.add_instruction(il.set_reg(lsz, dest, il.load(lsz, a)));
                    } else {
                        let a = il.add(
                            4,
                            il.reg(4, ebp()),
                            il.const_int(4, OBJECT_PTR_OFFSET as u64),
                        );
                        il.add_instruction(il.set_reg(4, dest, il.load(4, a)));
                    }
                }
                LoadSource::Memory => {
                    let obj_tmp = s.alloc();
                    if mn.starts_with("FMem") || mn.starts_with("WMem") {
                        let off = op_frame_offset(operands).unwrap_or(OBJECT_PTR_OFFSET as i16);
                        let a = il.add(4, il.reg(4, ebp()), il.const_int(4, off as i32 as u64));
                        il.add_instruction(il.set_reg(4, obj_tmp, il.load(4, a)));
                    } else {
                        let r = s.pop_eval();
                        il.add_instruction(il.set_reg(4, obj_tmp, il.reg(4, r)));
                    };
                    if let Some(off) = op_member_offset(operands) {
                        let mem = il.add(4, il.reg(4, obj_tmp), il.const_int(4, off as u64));
                        il.add_instruction(il.set_reg(sz, dest, il.load(sz, mem)));
                    } else {
                        il.add_instruction(il.set_reg(sz, dest, il.load(sz, il.reg(4, obj_tmp))));
                    }
                }
                LoadSource::Indirect => {
                    if mn.starts_with("Ary1") || mn.starts_with("Ary") {
                        let idx = s.pop_eval();
                        let arr = s.pop_eval();
                        let elem_addr = il.add(
                            4,
                            il.reg(4, arr),
                            il.mul(4, il.reg(4, idx), il.const_int(4, sz as u64)),
                        );
                        il.add_instruction(il.set_reg(sz, dest, il.load(sz, elem_addr)));
                    } else if mn.starts_with("ILd") || mn.starts_with("ImpAd") {
                        if let Some(off) = op_frame_offset(operands) {
                            let ptr_addr =
                                il.add(4, il.reg(4, ebp()), il.const_int(4, off as i32 as u64));
                            let ptr = il.load(4, ptr_addr);
                            il.add_instruction(il.set_reg(sz, dest, il.load(sz, ptr)));
                        } else {
                            il.add_instruction(il.set_reg(sz, dest, il.unimplemented()));
                        }
                    } else {
                        if info.pops > 0 {
                            s.pop_eval_n(info.pops.max(0) as u32);
                        }
                        il.add_instruction(il.set_reg(sz, dest, il.load(sz, il.unimplemented())));
                    }
                }
            }
            true
        }

        OpcodeSemantics::Store { target } => {
            let src = if fpu { s.pop_fpu() } else { s.pop_eval() };
            for _ in 1..info.pops.max(1) {
                s.pop_eval();
            }

            match target {
                StoreTarget::Frame => {
                    if let Some(off) = op_frame_offset(operands) {
                        let a = il.add(4, il.reg(4, ebp()), il.const_int(4, off as i32 as u64));
                        let ssz = if fpu { 4 } else { sz };
                        il.add_instruction(il.store(ssz, a, il.reg(ssz, src)));
                    } else {
                        il.add_instruction(il.nop());
                    }
                }
                StoreTarget::Memory => {
                    let obj_tmp = s.alloc();
                    if mn.starts_with("FMem") || mn.starts_with("WMem") {
                        let off = op_frame_offset(operands).unwrap_or(OBJECT_PTR_OFFSET as i16);
                        let a = il.add(4, il.reg(4, ebp()), il.const_int(4, off as i32 as u64));
                        il.add_instruction(il.set_reg(4, obj_tmp, il.load(4, a)));
                    } else {
                        let r = s.pop_eval();
                        il.add_instruction(il.set_reg(4, obj_tmp, il.reg(4, r)));
                    };
                    if let Some(off) = op_member_offset(operands) {
                        let mem = il.add(4, il.reg(4, obj_tmp), il.const_int(4, off as u64));
                        il.add_instruction(il.store(sz, mem, il.reg(sz, src)));
                    } else {
                        il.add_instruction(il.store(sz, il.reg(4, obj_tmp), il.reg(sz, src)));
                    }
                }
                StoreTarget::Indirect => {
                    if mn.starts_with("Ary1") || mn.starts_with("Ary") {
                        let idx = s.pop_eval();
                        let arr = s.pop_eval();
                        let elem_addr = il.add(
                            4,
                            il.reg(4, arr),
                            il.mul(4, il.reg(4, idx), il.const_int(4, sz as u64)),
                        );
                        il.add_instruction(il.store(sz, elem_addr, il.reg(sz, src)));
                    } else if mn.starts_with("ISt") || mn.starts_with("ImpAd") {
                        if let Some(off) = op_frame_offset(operands) {
                            let ptr_addr =
                                il.add(4, il.reg(4, ebp()), il.const_int(4, off as i32 as u64));
                            let ptr = il.load(4, ptr_addr);
                            il.add_instruction(il.store(sz, ptr, il.reg(sz, src)));
                        } else {
                            il.add_instruction(il.store(sz, il.unimplemented(), il.reg(sz, src)));
                        }
                    } else {
                        il.add_instruction(il.store(sz, il.unimplemented(), il.reg(sz, src)));
                    }
                }
            }
            true
        }

        OpcodeSemantics::Arithmetic { op } => {
            let rhs = if fpu { s.pop_fpu() } else { s.pop_eval() };
            let lhs = if fpu { s.pop_fpu() } else { s.pop_eval() };
            if info.pops > 2 {
                s.pop_eval_n((info.pops - 2) as u32);
            }
            let dest = if fpu { s.push_fpu() } else { s.push_eval() };
            if info.pushes > 1 {
                s.push_eval_n(info.pushes - 1);
            }
            let l = il.reg(sz, lhs);
            let r = il.reg(sz, rhs);
            if fpu {
                match op {
                    ArithOp::Add => il.add_instruction(il.set_reg(sz, dest, il.fadd(sz, l, r))),
                    ArithOp::Sub => il.add_instruction(il.set_reg(sz, dest, il.fsub(sz, l, r))),
                    ArithOp::Mul => il.add_instruction(il.set_reg(sz, dest, il.fmul(sz, l, r))),
                    ArithOp::Div | ArithOp::IDiv => {
                        il.add_instruction(il.set_reg(sz, dest, il.fdiv(sz, l, r)))
                    }
                    _ => il.add_instruction(il.set_reg(sz, dest, il.unimplemented())),
                };
            } else {
                match op {
                    ArithOp::Add => il.add_instruction(il.set_reg(sz, dest, il.add(sz, l, r))),
                    ArithOp::Sub => il.add_instruction(il.set_reg(sz, dest, il.sub(sz, l, r))),
                    ArithOp::Mul => il.add_instruction(il.set_reg(sz, dest, il.mul(sz, l, r))),
                    ArithOp::Div | ArithOp::IDiv => {
                        il.add_instruction(il.set_reg(sz, dest, il.divs(sz, l, r)))
                    }
                    ArithOp::Mod => il.add_instruction(il.set_reg(sz, dest, il.mods(sz, l, r))),
                    ArithOp::And => il.add_instruction(il.set_reg(sz, dest, il.and(sz, l, r))),
                    ArithOp::Or => il.add_instruction(il.set_reg(sz, dest, il.or(sz, l, r))),
                    ArithOp::Xor => il.add_instruction(il.set_reg(sz, dest, il.xor(sz, l, r))),
                    _ => il.add_instruction(il.set_reg(sz, dest, il.unimplemented())),
                };
            }
            true
        }

        OpcodeSemantics::Unary { op } => {
            if info.fpu_inplace {
                // FPU in-place: peek TOS, apply op, write back
                let tos = s
                    .fpu
                    .last()
                    .copied()
                    .map(LowLevelILTempRegister::new)
                    .unwrap_or_else(|| s.alloc());
                let v = il.reg(sz, tos);
                match op {
                    ArithOp::Neg => il.add_instruction(il.set_reg(sz, tos, il.fneg(sz, v))),
                    ArithOp::Abs => il.add_instruction(il.set_reg(sz, tos, il.fabs(sz, v))),
                    _ => il.add_instruction(il.set_reg(sz, tos, il.ftrunc(sz, v))),
                };
            } else {
                let src = if fpu { s.pop_fpu() } else { s.pop_eval() };
                let dest = if fpu { s.push_fpu() } else { s.push_eval() };
                let v = il.reg(sz, src);
                match (fpu, op) {
                    (true, ArithOp::Neg) => {
                        il.add_instruction(il.set_reg(sz, dest, il.fneg(sz, v)))
                    }
                    (true, ArithOp::Abs) => {
                        il.add_instruction(il.set_reg(sz, dest, il.fabs(sz, v)))
                    }
                    (true, _) => il.add_instruction(il.set_reg(sz, dest, il.ftrunc(sz, v))),
                    (false, ArithOp::Neg) => {
                        il.add_instruction(il.set_reg(sz, dest, il.neg(sz, v)))
                    }
                    (false, ArithOp::Not) => {
                        il.add_instruction(il.set_reg(sz, dest, il.not(sz, v)))
                    }
                    (false, _) => il.add_instruction(il.set_reg(sz, dest, il.unimplemented())),
                };
            }
            true
        }

        OpcodeSemantics::Compare => {
            let rhs = if fpu { s.pop_fpu() } else { s.pop_eval() };
            let lhs = if fpu { s.pop_fpu() } else { s.pop_eval() };
            if info.pops > 2 {
                s.pop_eval_n((info.pops - 2) as u32);
            }
            let dest = s.push_eval();
            let (fl, k) = cmp_kind(mn);
            let l = il.reg(sz, lhs);
            let r = il.reg(sz, rhs);
            match (fl, k) {
                (false, 1) => il.add_instruction(il.set_reg(4, dest, il.cmp_ne(sz, l, r))),
                (false, 2) => il.add_instruction(il.set_reg(4, dest, il.cmp_sgt(sz, l, r))),
                (false, 3) => il.add_instruction(il.set_reg(4, dest, il.cmp_sge(sz, l, r))),
                (false, 4) => il.add_instruction(il.set_reg(4, dest, il.cmp_slt(sz, l, r))),
                (false, 5) => il.add_instruction(il.set_reg(4, dest, il.cmp_sle(sz, l, r))),
                (false, _) => il.add_instruction(il.set_reg(4, dest, il.cmp_e(sz, l, r))),
                (true, 1) => il.add_instruction(il.set_reg(4, dest, il.fcmp_ne(sz, l, r))),
                (true, 2) => il.add_instruction(il.set_reg(4, dest, il.fcmp_gt(sz, l, r))),
                (true, 3) => il.add_instruction(il.set_reg(4, dest, il.fcmp_ge(sz, l, r))),
                (true, 4) => il.add_instruction(il.set_reg(4, dest, il.fcmp_lt(sz, l, r))),
                (true, 5) => il.add_instruction(il.set_reg(4, dest, il.fcmp_le(sz, l, r))),
                (true, _) => il.add_instruction(il.set_reg(4, dest, il.fcmp_e(sz, l, r))),
            };
            true
        }

        OpcodeSemantics::Branch { conditional } => {
            if *conditional {
                s.pop_eval_n(info.pops.max(1) as u32);
            }
            for _ in 0..info.fpu_pops {
                s.pop_fpu();
            }

            let target = operands.iter().find_map(|o| match o {
                Some(Operand::JumpTarget(t)) => func_base.map(|b| b + *t as u64),
                _ => None,
            });
            let fall = addr + len as u64;

            if *conditional {
                let cond = s.alloc();
                if let Some(tgt) = target {
                    let nt = il.label_for_address(tgt).is_none();
                    let nf = il.label_for_address(fall).is_none();
                    let mut t = il
                        .label_for_address(tgt)
                        .unwrap_or_default();
                    let mut f = il
                        .label_for_address(fall)
                        .unwrap_or_default();
                    il.add_instruction(il.if_expr(il.reg(4, cond), &mut t, &mut f));
                    if nt {
                        il.mark_label(&mut t);
                        il.add_instruction(il.jump(il.const_ptr(tgt)));
                    }
                    if nf {
                        il.mark_label(&mut f);
                    }
                } else {
                    il.add_instruction(il.nop());
                }
            } else if let Some(tgt) = target {
                let nt = il.label_for_address(tgt).is_none();
                let mut t = il
                    .label_for_address(tgt)
                    .unwrap_or_default();
                il.add_instruction(il.goto(&mut t));
                if nt {
                    il.mark_label(&mut t);
                    il.add_instruction(il.jump(il.const_ptr(tgt)));
                }
            } else {
                il.add_instruction(il.nop());
            }
            true
        }

        OpcodeSemantics::Call { kind } => {
            let argc = call_arg_count(operands);
            if argc > 0 {
                s.pop_eval_n(argc);
            } else if info.pops > 0 {
                s.pop_eval_n(info.pops as u32);
            }

            match kind {
                CallKind::VCall => {
                    let this_reg = s.pop_eval();
                    if let Some((vtoff, _)) = op_vtable(operands) {
                        let vtable = il.load(4, il.reg(4, this_reg));
                        let method = il.load(4, il.add(4, vtable, il.const_int(4, vtoff as u64)));
                        il.add_instruction(il.call(method));
                    } else {
                        il.add_instruction(il.call(il.unimplemented()));
                    }
                }
                CallKind::ThisVCall => {
                    let this_addr = il.add(
                        4,
                        il.reg(4, ebp()),
                        il.const_int(4, OBJECT_PTR_OFFSET as u64),
                    );
                    let this_ptr = il.load(4, this_addr);
                    if let Some((vtoff, _)) = op_vtable(operands) {
                        let vtable = il.load(4, this_ptr);
                        let method = il.load(4, il.add(4, vtable, il.const_int(4, vtoff as u64)));
                        il.add_instruction(il.call(method));
                    } else if let Some(off) = op_member_offset(operands) {
                        let vtable = il.load(4, this_ptr);
                        let method = il.load(4, il.add(4, vtable, il.const_int(4, off as u64)));
                        il.add_instruction(il.call(method));
                    } else {
                        il.add_instruction(il.call(il.unimplemented()));
                    }
                }
                CallKind::ImpAdCall => {
                    let target_va = op_external(operands)
                        .and_then(|(import, _)| crate::arch::lookup_import_target(import));
                    match target_va {
                        Some(va) => il.add_instruction(il.call(il.const_ptr(va))),
                        None => il.add_instruction(il.call(il.const_ptr(0))),
                    }
                }
                CallKind::LateCall | CallKind::Other => {
                    il.add_instruction(il.call(il.unimplemented()));
                }
            }

            if info.pushes > 0 {
                let d = s.push_eval();
                il.add_instruction(il.set_reg(4, d, il.const_int(4, 0)));
                s.push_eval_n(info.pushes - 1);
            }
            if info.fpu_push > 0 {
                let d = s.push_fpu();
                il.add_instruction(il.set_reg(4, d, il.const_int(4, 0)));
            }
            true
        }

        OpcodeSemantics::Return => {
            il.add_instruction(il.ret(il.const_int(4, 0)));
            true
        }

        OpcodeSemantics::Convert { from, to } => {
            let from_fpu = from.map(|t| t.is_fpu()).unwrap_or(false) || info.fpu_pops > 0;
            let to_fpu = to.map(|t| t.is_fpu()).unwrap_or(false) || info.fpu_push > 0;
            let fsz = from
                .map(|t| t.eval_stack_bytes() as usize)
                .unwrap_or(4)
                .max(1);
            let tsz = to
                .map(|t| t.eval_stack_bytes() as usize)
                .unwrap_or(4)
                .max(1);

            let src = if from_fpu { s.pop_fpu() } else { s.pop_eval() };
            if info.pops > 1 {
                s.pop_eval_n((info.pops - 1) as u32);
            }
            let dest = if to_fpu { s.push_fpu() } else { s.push_eval() };
            if info.pushes > 1 {
                s.push_eval_n(info.pushes - 1);
            }

            let v = il.reg(fsz, src);
            if from_fpu && !to_fpu {
                il.add_instruction(il.set_reg(tsz, dest, il.float_to_int(tsz, v)));
            } else if !from_fpu && to_fpu {
                il.add_instruction(il.set_reg(tsz, dest, il.int_to_float(tsz, v)));
            } else {
                il.add_instruction(il.set_reg(tsz, dest, v));
            }
            true
        }

        OpcodeSemantics::Stack | OpcodeSemantics::Io => {
            s.pop_eval_n(info.pops.max(0) as u32);
            for _ in 0..info.fpu_pops {
                s.pop_fpu();
            }

            il.add_instruction(il.call(il.const_ptr(0)));

            if info.pushes > 0 {
                let d = s.push_eval();
                il.add_instruction(il.set_reg(4, d, il.const_int(4, 0)));
                s.push_eval_n(info.pushes - 1);
            }
            if info.fpu_push > 0 {
                let d = s.push_fpu();
                il.add_instruction(il.set_reg(4, d, il.const_int(4, 0)));
            }
            true
        }

        OpcodeSemantics::Unclassified => {
            il.add_instruction(il.unimplemented());
            s.pop_eval_n(info.pops.max(0) as u32);
            for _ in 0..info.fpu_pops {
                s.pop_fpu();
            }
            s.push_eval_n(info.pushes);
            for _ in 0..info.fpu_push {
                s.push_fpu();
            }
            true
        }
    }
}
