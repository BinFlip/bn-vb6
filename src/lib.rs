//! Binary Ninja plugin for VB6 P-Code analysis.
//!
//! This plugin auto-detects VB6 executables (EXE, DLL, OCX) when loaded in
//! Binary Ninja and enriches them with:
//!
//! - **Structure types**: Fifteen VB6 struct types and four enum types defined
//!   in Binary Ninja's type system, applied as overlays at correct VAs.
//! - **Symbols**: Named data and function symbols for all VB6 objects, methods,
//!   controls, and Declare imports.
//! - **Function discovery**: P-Code, native, thunk, and event handler entry
//!   points discovered via [`visualbasic::project::VbObject::code_entries`].
//! - **Custom architecture**: A `VB6-PCode` architecture that decodes P-Code
//!   instructions into readable mnemonics with LLIL lifting for the decompiler.
//!
//! # Modules
//!
//! - `analysis` — Parses the PE with [`visualbasic::VbProject`] and extracts
//!   all metadata into owned structures.
//! - `annotate` — Applies analysis results to the `BinaryView` (types,
//!   symbols, functions, comments).
//! - [`arch`] — Registers the `VB6-PCode` custom architecture and platform.
//! - [`lift`] — LLIL lifting for P-Code instructions (dual eval/FPU stack model).
//! - `types` — Defines VB6 struct types in Binary Ninja's type system.

mod analysis;
mod annotate;
mod arch;
mod lift;
mod types;

use std::{collections::HashSet, sync::Mutex};

use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt, register_binary_view_event},
    command::register_command,
};
use binaryninjacore_sys::BNBinaryViewEventType;

use analysis::CodeEntryKindOwned;

/// Re-entrancy guard keyed by `(start_address, length)` of the raw view.
///
/// Prevents duplicate analysis when Binary Ninja fires the initial-analysis
/// completion event multiple times for the same binary.
static ANALYZED: Mutex<Option<HashSet<(u64, u64)>>> = Mutex::new(None);

/// Run the full VB6 analysis pipeline on a [`BinaryView`].
///
/// Parses the PE as a VB6 project, logs a summary of discovered objects
/// and code entries, then applies all annotations (types, symbols, functions,
/// comments) to the view.
fn run_vb6_analysis(view: &BinaryView) {
    match analysis::analyze(view) {
        Ok(result) => {
            let all_entries: Vec<_> = result
                .objects
                .iter()
                .flat_map(|o| o.code_entries.iter())
                .collect();
            let count =
                |kind: CodeEntryKindOwned| all_entries.iter().filter(|e| e.kind == kind).count();

            log(&format!(
                "Parsed: {} objects, {} code entries ({} P-Code, {} native, {} thunks, {} events)",
                result.objects.len(),
                all_entries.len(),
                count(CodeEntryKindOwned::PCode),
                count(CodeEntryKindOwned::Native),
                count(CodeEntryKindOwned::NativeThunk),
                count(CodeEntryKindOwned::EventHandler),
            ));

            for obj in &result.objects {
                for ce in &obj.code_entries {
                    if ce.kind == CodeEntryKindOwned::PCode {
                        let name = ce.name.as_deref().unwrap_or("?");
                        let pcode_size = ce.pcode_size.unwrap_or(0);
                        log(&format!(
                            "  P-Code: {}.{} pcode=0x{:08x} size=0x{:04x}",
                            obj.name, name, ce.va, pcode_size
                        ));
                    }
                }
            }

            annotate::annotate(view, &result);

            log(&format!(
                "Done. Project: {} | {} | {} objects, {} code entries",
                result.project_name,
                if result.is_pcode { "P-Code" } else { "Native" },
                result.objects.len(),
                all_entries.len(),
            ));
        }
        Err(e) => {
            log_warn(&format!("VB6 analysis failed: {e}"));
        }
    }
}

/// Returns `true` if the view is a PE file (cheap string check, safe for any thread).
fn is_pe_view(view: &BinaryView) -> bool {
    view.view_type() == "PE"
}

/// Command handler for the manual "VB6 > Analyze VB6 Structures" menu entry.
struct AnalyzeVb6Command;

impl binaryninja::command::Command for AnalyzeVb6Command {
    fn action(&self, view: &BinaryView) {
        run_vb6_analysis(view);
    }

    fn valid(&self, view: &BinaryView) -> bool {
        is_pe_view(view)
    }
}

/// Log an informational message to the Binary Ninja log console under the "VB6" tag.
pub(crate) fn log(msg: &str) {
    binaryninja::logger::bn_log("VB6", binaryninja::logger::BnLogLevel::InfoLog, msg);
}

/// Log a warning message to the Binary Ninja log console under the "VB6" tag.
pub(crate) fn log_warn(msg: &str) {
    binaryninja::logger::bn_log("VB6", binaryninja::logger::BnLogLevel::WarningLog, msg);
}

/// Binary Ninja plugin entry point.
///
/// Registers the `VB6-PCode` custom architecture and platform, adds a manual
/// analysis command, and installs an auto-detection hook that triggers VB6
/// analysis on a worker thread whenever a PE file completes initial analysis.
#[unsafe(no_mangle)]
pub extern "C" fn CorePluginInit() -> bool {
    log("VB6 plugin loading...");

    arch::register();

    register_command(
        "VB6\\Analyze VB6 Structures",
        "Parse VB6 internal structures and annotate the binary with types, symbols, and comments",
        AnalyzeVb6Command,
    );

    register_binary_view_event(
        BNBinaryViewEventType::BinaryViewInitialAnalysisCompletionEvent,
        |view: &BinaryView| {
            let key = (view.start(), view.len());
            {
                let mut guard = ANALYZED.lock().unwrap();
                let set = guard.get_or_insert_with(HashSet::new);
                if !set.insert(key) {
                    return;
                }
            }

            if !is_pe_view(view) {
                return;
            }

            let view_ref = view.to_owned();
            binaryninja::worker_thread::execute_on_worker_thread("VB6 Analysis", move || {
                run_vb6_analysis(&view_ref);
            });
        },
    );

    log("VB6 plugin loaded successfully");
    true
}
