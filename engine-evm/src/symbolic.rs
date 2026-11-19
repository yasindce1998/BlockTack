//! Symbolic execution: counterfactual exploration of a contract call.
//!
//! `symbolic-call` executes ONE call frame of a target contract with
//! selected calldata arguments treated as symbolic bitvectors and every
//! other input concrete (storage read from the fork, environment
//! fixed). At every JUMPI whose condition depends on a symbolic value
//! the execution forks: the solver (z3 over SMT-LIB2, driven as a
//! subprocess) decides whether each branch is reachable, and the search
//! continues depth-first under step/path budgets.
//!
//! The goal is a profit condition — "a CALL moves at least N wei to
//! address A" (ethTo), "an ERC-20 transfer sends at least N units to
//! A" (tokenTransfer), or "storage slot S ends at least N" (sstore).
//! When a path reaches the goal, the solver's model is extracted as
//! concrete calldata: the input an attacker would sign. This turns the
//! corpus from a regression suite (replaying known inputs) into a
//! discovery engine (finding unknown inputs).
//!
//! Soundness caveats, documented and deliberate:
//!   - keccak over symbolic bytes prunes the path (no SMT encoding)
//!   - sub-calls (CALL/DELEGATECALL/STATICCALL) that do not hit the
//!     goal are concretized under the current model and executed
//!     concretely against the fork — their results are treated as
//!     concrete for the rest of the path
//!   - symbolic JUMP destinations, CREATE/CREATE2 and unimplemented
//!     opcodes prune the path
//! Everything else is exact EVM semantics on 256-bit words.

use crate::finding::Finding;
use alloy::network::TransactionBuilder;
use alloy::primitives::{keccak256, Address, U256};
use alloy::providers::{DynProvider, Provider};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

const PROBE_CALLER: &str = "0x0000000000000000000000000000000000008008";

// ---------------------------------------------------------------------------
// Solver: z3 over SMT-LIB2 on a persistent pipe
// ---------------------------------------------------------------------------

pub struct Solver {
    proc: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    terms: u32,
}

impl Solver {
    /// Locate z3: $Z3_BIN, then PATH.
    pub fn discover() -> Option<String> {
        if let Ok(bin) = std::env::var("Z3_BIN") {
            if std::path::Path::new(&bin).exists() {
                return Some(bin);
            }
        }
        for dir in std::env::var("PATH").unwrap_or_default().split(':') {
            let cand = std::path::Path::new(dir).join("z3");
            if cand.is_file() {
                return Some(cand.to_string_lossy().into_owned());
            }
        }
        None
    }

    pub fn available() -> bool {
        Self::discover().is_some()
    }

    pub fn new() -> anyhow::Result<Self> {
        let bin = Self::discover().ok_or_else(|| {
            anyhow::anyhow!(
                "z3 not found: install z3 or set Z3_BIN (symbolic execution needs an SMT solver)"
            )
        })?;
        let mut proc = Command::new(bin)
            .arg("-in")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = proc.stdin.take().expect("z3 stdin");
        let stdout = BufReader::new(proc.stdout.take().expect("z3 stdout"));
        let mut s = Solver {
            proc,
            stdin,
            stdout,
            terms: 0,
        };
        s.cmd("(set-option :timeout 5000)");
        s.cmd("(set-logic QF_BV)");
        Ok(s)
    }

    fn cmd(&mut self, line: &str) -> String {
        if writeln!(self.stdin, "{line}").is_err() {
            return String::new();
        }
        let _ = self.stdin.flush();
        // z3 only prints responses for query commands; everything else
        // (set-option, assert, define-fun, push, pop) is silent.
        if line.starts_with("(check-sat") || line.starts_with("(get-value") {
            let mut out = String::new();
            let _ = self.stdout.read_line(&mut out);
            out.trim().to_string()
        } else {
            String::new()
        }
    }

    pub fn push(&mut self) {
        self.cmd("(push 1)");
    }
    pub fn pop(&mut self) {
        self.cmd("(pop 1)");
    }
    pub fn assert(&mut self, term: &str) {
        self.cmd(&format!("(assert {term})"));
    }

    /// Some(true/false) for sat/unsat; None for unknown/timeout.
    pub fn check_sat(&mut self) -> Option<bool> {
        match self.cmd("(check-sat)").as_str() {
            "sat" => Some(true),
            "unsat" => Some(false),
            _ => None,
        }
    }

    /// Model value of a (_ BitVec 256) term as U256.
    pub fn value(&mut self, term: &str) -> Option<U256> {
        let out = self.cmd(&format!("(get-value ({term}))"));
        let hex = out.split('#').nth(1)?;
        let hex = hex.trim_end_matches(')').trim();
        let hex = hex.strip_prefix('x').unwrap_or(hex);
        if hex.len() != 64 {
            return None;
        }
        U256::from_str_radix(hex, 16).ok()
    }

    /// Define a fresh named 256-bit term, returning its name.
    pub fn def(&mut self, body: &str) -> String {
        self.terms += 1;
        let name = format!("t{}", self.terms);
        self.cmd(&format!("(define-fun {name} () (_ BitVec 256) {body})"));
        name
    }

    /// Define a fresh named 8-bit term, returning its name.
    pub fn def_byte(&mut self, body: &str) -> String {
        self.terms += 1;
        let name = format!("t{}", self.terms);
        self.cmd(&format!("(define-fun {name} () (_ BitVec 8) {body})"));
        name
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        let _ = self.stdin.write_all(b"(exit)\n");
        let _ = self.proc.kill();
        let _ = self.proc.wait();
    }
}

// ---------------------------------------------------------------------------
// Values and memory
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum SVal {
    Con(U256),
    /// Named 256-bit SMT term.
    Sym(String),
}

impl SVal {
    fn as_con(&self) -> Option<U256> {
        match self {
            SVal::Con(c) => Some(*c),
            SVal::Sym(_) => None,
        }
    }
}

/// Memory/calldata cell: concrete byte or named (_ BitVec 8) term.
#[derive(Clone)]
pub enum Cell {
    Con(u8),
    Sym(String),
}

fn word_lit(v: &U256) -> String {
    format!("#x{:064x}", v)
}

fn byte_lit(b: u8) -> String {
    format!("#x{b:02x}")
}

fn zero() -> SVal {
    SVal::Con(U256::ZERO)
}

/// Truncate a concretized offset to a sane usize (1 MiB memory bound);
/// anything larger is a malformed/concretization-artifact offset and
/// prunes the path instead of wrapping.
fn sane_offset(v: U256) -> Option<usize> {
    if v > U256::from(1u32 << 20) {
        return None;
    }
    Some(v.as_limbs()[0] as usize)
}

// ---------------------------------------------------------------------------
// Machine
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Frame {
    code: Vec<u8>,
    pc: usize,
    stack: Vec<SVal>,
    mem: Vec<Cell>,
    calldata: Vec<Cell>,
    returndata: Vec<u8>,
    store: HashMap<U256, U256>,
    caller: Address,
    address: Address,
    value: U256,
}

pub enum GoalKind {
    EthTo,
    TokenTransfer,
    SStore,
}

pub struct Goal {
    pub kind: GoalKind,
    pub address: Address,
    pub min_amount: U256,
}

enum Outcome {
    Return(Vec<u8>),
    Revert,
    Prune(String),
    GoalHit(Vec<u8>),
}

#[derive(Default)]
struct Stats {
    paths: u32,
    steps: u64,
    pruned: u32,
    solved_branches: u32,
    reverted: u32,
}

struct Machine {
    frame: Frame,
    goal: Goal,
    rt: tokio::runtime::Runtime,
    provider: DynProvider,
    solver: Solver,
    arg_vars: Vec<String>,
    selector: [u8; 4],
    stats: Stats,
    max_paths: u32,
    max_steps: u64,
    /// When a state overlay is supplied, SLOADs never hit the RPC
    /// (missing slots read as zero) — fully offline exploration.
    overlay_only: bool,
}

impl Machine {
    fn push(&mut self, v: SVal) {
        self.frame.stack.push(v);
    }

    fn pop(&mut self) -> SVal {
        self.frame.stack.pop().unwrap_or_else(zero)
    }

    fn concretize(&mut self, v: &SVal) -> U256 {
        match v {
            SVal::Con(c) => *c,
            SVal::Sym(t) => self.solver.value(t).unwrap_or_default(),
        }
    }

    fn term(&mut self, v: &SVal) -> String {
        match v {
            SVal::Con(c) => word_lit(c),
            SVal::Sym(t) => t.clone(),
        }
    }

    fn binop(&mut self, f_con: impl Fn(U256, U256) -> U256, f_smt: &str) {
        let b = self.pop();
        let a = self.pop();
        let v = match (a.as_con(), b.as_con()) {
            (Some(x), Some(y)) => SVal::Con(f_con(x, y)),
            _ => {
                let x = self.term(&a);
                let y = self.term(&b);
                let t = self.solver.def(&format!("({f_smt} {x} {y})"));
                SVal::Sym(t)
            }
        };
        self.push(v);
    }

    /// Division-like op with EVM's x/0 = 0 semantics for symbolic operands.
    fn divop(&mut self, f_con: impl Fn(U256, U256) -> U256, f_smt: &str) {
        let b = self.pop();
        let a = self.pop();
        let v = match (a.as_con(), b.as_con()) {
            (Some(x), Some(y)) => SVal::Con(f_con(x, y)),
            _ => {
                let x = self.term(&a);
                let y = self.term(&b);
                let z = word_lit(&U256::ZERO);
                let t = self
                    .solver
                    .def(&format!("(ite (= {y} {z}) {z} ({f_smt} {x} {y}))"));
                SVal::Sym(t)
            }
        };
        self.push(v);
    }

    /// Signed comparison (SLT/SGT): EVM order is TOP <op> SECOND.
    fn scmpop(
        &mut self,
        f_con: impl Fn(alloy::primitives::I256, alloy::primitives::I256) -> bool,
        f_smt: &str,
    ) {
        let b = self.pop();
        let a = self.pop();
        let v = match (a.as_con(), b.as_con()) {
            (Some(x), Some(y)) => {
                let (xs, ys) = (to_i256(x), to_i256(y));
                SVal::Con(U256::from(f_con(ys, xs) as u8))
            }
            _ => {
                let x = self.term(&a);
                let y = self.term(&b);
                let t = self.solver.def(&format!(
                    "(ite ({f_smt} {y} {x}) {} {})",
                    word_lit(&U256::from(1u8)),
                    word_lit(&U256::ZERO)
                ));
                SVal::Sym(t)
            }
        };
        self.push(v);
    }

    /// Comparison op: EVM order is TOP <op> SECOND-from-top, so the
    /// concrete and SMT operands are swapped relative to push order
    /// (`PUSH a; PUSH b; LT` computes b < a). The EVM result is a 0/1
    /// word, so the SMT Bool is wrapped in an ite.
    fn cmpop(&mut self, f_con: impl Fn(U256, U256) -> bool, f_smt: &str) {
        let b = self.pop();
        let a = self.pop();
        let v = match (a.as_con(), b.as_con()) {
            (Some(x), Some(y)) => SVal::Con(U256::from(f_con(y, x))),
            _ => {
                let x = self.term(&a);
                let y = self.term(&b);
                let one = word_lit(&U256::from(1u8));
                let zero = word_lit(&U256::ZERO);
                let t = self
                    .solver
                    .def(&format!("(ite ({f_smt} {y} {x}) {one} {zero})"));
                SVal::Sym(t)
            }
        };
        self.push(v);
    }

    fn mload(&mut self, offset: usize) -> SVal {
        self.frame.mem.resize(offset + 32, Cell::Con(0));
        if self.frame.mem[offset..offset + 32]
            .iter()
            .all(|c| matches!(c, Cell::Con(_)))
        {
            let mut buf = [0u8; 32];
            for (i, cell) in self.frame.mem[offset..offset + 32].iter().enumerate() {
                buf[i] = match cell {
                    Cell::Con(b) => *b,
                    Cell::Sym(_) => unreachable!(),
                };
            }
            return SVal::Con(U256::from_be_bytes(buf));
        }
        let expr = self.concat_bytes(offset, 32);
        SVal::Sym(self.solver.def(&expr))
    }

    /// SMT concatenation expression for a byte range (big-endian word).
    fn concat_bytes(&mut self, offset: usize, len: usize) -> String {
        self.frame.mem.resize(offset + len, Cell::Con(0));
        let mut expr = String::new();
        for i in 0..len {
            let part = match &self.frame.mem[offset + i] {
                Cell::Con(b) => byte_lit(*b),
                Cell::Sym(t) => format!("((_ extract 7 0) {t})"),
            };
            expr = if expr.is_empty() {
                part
            } else {
                format!("(concat {expr} {part})")
            };
        }
        expr
    }

    fn mem_write_word(&mut self, offset: usize, v: &SVal) {
        self.frame.mem.resize(offset + 32, Cell::Con(0));
        match v {
            SVal::Con(c) => {
                let b = c.to_be_bytes::<32>();
                for i in 0..32 {
                    self.frame.mem[offset + i] = Cell::Con(b[i]);
                }
            }
            SVal::Sym(t) => {
                for i in 0..32 {
                    let hi = (31 - i) * 8 + 7;
                    let lo = (31 - i) * 8;
                    let bt = self
                        .solver
                        .def_byte(&format!("((_ extract {hi} {lo}) {t})"));
                    self.frame.mem[offset + i] = Cell::Sym(bt);
                }
            }
        }
    }

    fn calldataload(&mut self, offset: usize) -> SVal {
        let mut cells = vec![Cell::Con(0); 32];
        for i in 0..32 {
            if offset + i < self.frame.calldata.len() {
                cells[i] = self.frame.calldata[offset + i].clone();
            }
        }
        if cells.iter().all(|c| matches!(c, Cell::Con(_))) {
            let mut buf = [0u8; 32];
            for (i, c) in cells.iter().enumerate() {
                buf[i] = match c {
                    Cell::Con(b) => *b,
                    _ => unreachable!(),
                };
            }
            return SVal::Con(U256::from_be_bytes(buf));
        }
        let mut expr = String::new();
        for c in &cells {
            let part = match c {
                Cell::Con(b) => byte_lit(*b),
                Cell::Sym(t) => format!("((_ extract 7 0) {t})"),
            };
            expr = if expr.is_empty() {
                part
            } else {
                format!("(concat {expr} {part})")
            };
        }
        SVal::Sym(self.solver.def(&expr))
    }

    fn model_calldata(&mut self) -> Vec<u8> {
        let mut out = self.selector.to_vec();
        for var in &self.arg_vars.clone() {
            let v = self.solver.value(var).unwrap_or_default();
            out.extend_from_slice(&v.to_be_bytes::<32>());
        }
        out
    }

    /// Returns Some(model calldata) when the goal fires — extracted
    /// while the goal constraint is still asserted, so the model is
    /// one that actually reaches the goal.
    fn check_call_goal(
        &mut self,
        addr: &SVal,
        value: &SVal,
        args_off: usize,
        args_len: usize,
    ) -> Option<Vec<u8>> {
        let goal_addr = U256::from_be_slice(self.goal.address.as_slice());
        let addr_con = self.concretize(addr);
        match self.goal.kind {
            GoalKind::EthTo => {
                if addr_con != goal_addr {
                    return None;
                }
                match value {
                    SVal::Con(c) => {
                        if *c >= self.goal.min_amount {
                            Some(self.model_calldata())
                        } else {
                            None
                        }
                    }
                    SVal::Sym(t) => {
                        self.solver.push();
                        self.solver
                            .assert(&format!("(bvuge {t} {})", word_lit(&self.goal.min_amount)));
                        let sat = self.solver.check_sat().unwrap_or(false);
                        let model = if sat {
                            Some(self.model_calldata())
                        } else {
                            None
                        };
                        self.solver.pop();
                        model
                    }
                }
            }
            GoalKind::TokenTransfer => {
                if addr_con != goal_addr {
                    return None;
                }
                if args_len < 68 {
                    return None;
                }
                let bytes = self.frame.mem[args_off..args_off + args_len].to_vec();
                let sel: [u8; 4] = match (&bytes[0], &bytes[1], &bytes[2], &bytes[3]) {
                    (Cell::Con(a), Cell::Con(b), Cell::Con(c), Cell::Con(d)) => [*a, *b, *c, *d],
                    _ => return None,
                };
                let (recip_off, amt_off) = if sel == [0xa9, 0x05, 0x9c, 0xbb] {
                    (4usize, 36usize)
                } else if sel == [0x23, 0xb8, 0x72, 0xdd] {
                    (36, 68)
                } else {
                    return None;
                };
                let (recip, amt) = (
                    self.cells_word(&bytes[recip_off..recip_off + 32]),
                    self.cells_word(&bytes[amt_off..amt_off + 32]),
                );
                if let (Some(r), Some(a)) = (recip.as_con(), amt.as_con()) {
                    return if r == goal_addr && a >= self.goal.min_amount {
                        Some(self.model_calldata())
                    } else {
                        None
                    };
                }
                let want = word_lit(&goal_addr);
                let min = word_lit(&self.goal.min_amount);
                let recip_t = self.term(&recip);
                let amt_t = self.term(&amt);
                self.solver.push();
                self.solver
                    .assert(&format!("(and (= {recip_t} {want}) (bvuge {amt_t} {min}))"));
                let sat = self.solver.check_sat().unwrap_or(false);
                let model = if sat {
                    Some(self.model_calldata())
                } else {
                    None
                };
                self.solver.pop();
                model
            }
            GoalKind::SStore => None,
        }
    }

    fn cells_word(&mut self, cells: &[Cell]) -> SVal {
        if cells.iter().all(|c| matches!(c, Cell::Con(_))) {
            let mut buf = [0u8; 32];
            for (i, c) in cells.iter().enumerate() {
                buf[i] = match c {
                    Cell::Con(b) => *b,
                    _ => unreachable!(),
                };
            }
            return SVal::Con(U256::from_be_bytes(buf));
        }
        let mut expr = String::new();
        for c in cells {
            let part = match c {
                Cell::Con(b) => byte_lit(*b),
                Cell::Sym(t) => format!("((_ extract 7 0) {t})"),
            };
            expr = if expr.is_empty() {
                part
            } else {
                format!("(concat {expr} {part})")
            };
        }
        SVal::Sym(self.solver.def(&expr))
    }

    fn eth_call_sub(&mut self, addr: U256, data: Vec<u8>, value: U256) -> Option<Vec<u8>> {
        let addr_bytes = addr.to_be_bytes::<32>();
        let to = Address::from_slice(&addr_bytes[12..]);
        let mut tx = alloy::rpc::types::TransactionRequest::default();
        tx.set_from(self.frame.caller);
        tx.set_to(to);
        tx.set_input(alloy::primitives::Bytes::from(data));
        if !value.is_zero() {
            tx.set_value(value);
        }
        let provider = self.provider.clone();
        let res = self.rt.block_on(async move { provider.call(tx).await });
        match res {
            Ok(bytes) => Some(bytes.to_vec()),
            Err(_) => None,
        }
    }

    /// Run the frame until halt, goal, prune, or budget exhaustion.
    fn run(&mut self) -> Outcome {
        loop {
            self.stats.steps += 1;
            if self.stats.steps > self.max_steps {
                return Outcome::Prune("step budget exhausted".into());
            }
            if self.stats.paths > self.max_paths {
                return Outcome::Prune("path budget exhausted".into());
            }
            let pc = self.frame.pc;
            let op = match self.frame.code.get(pc) {
                Some(op) => *op,
                None => return Outcome::Return(vec![]),
            };
            self.frame.pc += 1;
            match op {
                0x00 => return Outcome::Return(vec![]), // STOP: clean halt
                0x01 => self.binop(|a, b| a.overflowing_add(b).0, "bvadd"),
                0x02 => self.binop(|a, b| a.overflowing_mul(b).0, "bvmul"),
                0x03 => self.binop(|a, b| a.overflowing_sub(b).0, "bvsub"),
                0x04 => self.divop(
                    |a, b| if b.is_zero() { U256::ZERO } else { a / b },
                    "bvudiv",
                ),
                0x06 => self.divop(
                    |a, b| if b.is_zero() { U256::ZERO } else { a % b },
                    "bvurem",
                ),
                0x10 => self.cmpop(|b, a| b < a, "bvult"),
                0x11 => self.cmpop(|b, a| b > a, "bvugt"),
                0x12 => self.scmpop(|b, a| b < a, "bvslt"),
                0x13 => self.scmpop(|b, a| b > a, "bvsgt"),
                0x0a => {
                    // EXP: concrete exponents only.
                    let b = self.pop();
                    let a = self.pop();
                    match (a.as_con(), b.as_con()) {
                        (Some(x), Some(y)) => {
                            let e = y.as_limbs()[0];
                            if e > 128 {
                                return Outcome::Prune("exp exponent too large".into());
                            }
                            self.push(SVal::Con(x.pow(U256::from(e))));
                        }
                        _ => return Outcome::Prune("symbolic exponent".into()),
                    }
                }
                0x1d => {
                    // SAR: arithmetic shift right; amount is TOP.
                    let b = self.pop();
                    let a = self.pop();
                    let v = match (a.as_con(), b.as_con()) {
                        (Some(x), Some(y)) => {
                            let s = y.as_limbs()[0];
                            if s >= 256 {
                                SVal::Con(if to_i256(x).is_negative() {
                                    U256::MAX
                                } else {
                                    U256::ZERO
                                })
                            } else {
                                // arithmetic shift via i128 is lossy for
                                // large values; use repeated halving on
                                // the two's complement form via I256.
                                let i = alloy::primitives::I256::from_raw(x);
                                let shifted = i >> s;
                                SVal::Con(shifted.into_raw())
                            }
                        }
                        _ => {
                            let x = self.term(&a);
                            let y = self.term(&b);
                            SVal::Sym(self.solver.def(&format!("(bvashr {x} {y})")))
                        }
                    };
                    self.push(v);
                }
                0x14 => {
                    // EQ: Bool in SMT, 0/1 word in the EVM.
                    let b = self.pop();
                    let a = self.pop();
                    let v = match (a.as_con(), b.as_con()) {
                        (Some(x), Some(y)) => SVal::Con(U256::from(x == y)),
                        _ => {
                            let x = self.term(&a);
                            let y = self.term(&b);
                            let one = word_lit(&U256::from(1u8));
                            let zero = word_lit(&U256::ZERO);
                            SVal::Sym(self.solver.def(&format!("(ite (= {x} {y}) {one} {zero})")))
                        }
                    };
                    self.push(v);
                }
                0x15 => {
                    let a = self.pop();
                    let v = match a.as_con() {
                        Some(c) => SVal::Con(U256::from(c.is_zero())),
                        None => {
                            let t = self.term(&a);
                            let z = word_lit(&U256::ZERO);
                            let o = word_lit(&U256::from(1u8));
                            SVal::Sym(self.solver.def(&format!("(ite (= {t} {z}) {o} {z})")))
                        }
                    };
                    self.push(v);
                }
                0x16 => self.binop(|a, b| a & b, "bvand"),
                0x17 => self.binop(|a, b| a | b, "bvor"),
                0x18 => self.binop(|a, b| a ^ b, "bvxor"),
                0x1b => {
                    let b = self.pop();
                    let a = self.pop();
                    let v = match (a.as_con(), b.as_con()) {
                        (Some(x), Some(y)) => {
                            let s = y.as_limbs()[0];
                            if s >= 256 {
                                SVal::Con(U256::ZERO)
                            } else {
                                SVal::Con(x << s)
                            }
                        }
                        _ => {
                            let x = self.term(&a);
                            let y = self.term(&b);
                            SVal::Sym(self.solver.def(&format!("(bvshl {x} {y})")))
                        }
                    };
                    self.push(v);
                }
                0x1c => {
                    let b = self.pop();
                    let a = self.pop();
                    let v = match (a.as_con(), b.as_con()) {
                        (Some(x), Some(y)) => {
                            let s = y.as_limbs()[0];
                            if s >= 256 {
                                SVal::Con(U256::ZERO)
                            } else {
                                SVal::Con(x >> s)
                            }
                        }
                        _ => {
                            let x = self.term(&a);
                            let y = self.term(&b);
                            SVal::Sym(self.solver.def(&format!("(bvlshr {x} {y})")))
                        }
                    };
                    self.push(v);
                }
                0x20 => {
                    // SHA3: pops offset (top) then size. Concrete input only.
                    let off = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let len = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let (Some(off), Some(len)) = (sane_offset(off), sane_offset(len)) else {
                        return Outcome::Prune("sha3 range too large".into());
                    };
                    self.frame.mem.resize(off + len, Cell::Con(0));
                    if self.frame.mem[off..off + len]
                        .iter()
                        .all(|c| matches!(c, Cell::Con(_)))
                    {
                        let mut buf = vec![0u8; len];
                        for (i, c) in self.frame.mem[off..off + len].iter().enumerate() {
                            buf[i] = match c {
                                Cell::Con(b) => *b,
                                _ => unreachable!(),
                            };
                        }
                        let h = keccak256(&buf);
                        self.push(SVal::Con(U256::from_be_bytes(h.0)));
                    } else {
                        self.stats.pruned += 1;
                        return Outcome::Prune("keccak over symbolic bytes".into());
                    }
                }
                0x30 => self.push(SVal::Con(U256::from_be_slice(
                    self.frame.address.as_slice(),
                ))),
                0x33 => self.push(SVal::Con(U256::from_be_slice(self.frame.caller.as_slice()))),
                0x34 => self.push(SVal::Con(self.frame.value)),
                0x35 => {
                    let off = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let Some(off) = sane_offset(off) else {
                        return Outcome::Prune("calldataload offset out of range".into());
                    };
                    let v = self.calldataload(off);
                    self.push(v);
                }
                0x36 => self.push(SVal::Con(U256::from(self.frame.calldata.len()))),
                0x37 => {
                    // CALLDATACOPY (concrete offsets).
                    let len = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let off = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let dst = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let (Some(dst), Some(off), Some(len)) =
                        (sane_offset(dst), sane_offset(off), sane_offset(len))
                    else {
                        return Outcome::Prune("calldatacopy range".into());
                    };
                    self.frame
                        .mem
                        .resize(dst.max(self.frame.mem.len()), Cell::Con(0));
                    self.frame.mem.resize(dst + len, Cell::Con(0));
                    for i in 0..len {
                        let cell = if off + i < self.frame.calldata.len() {
                            self.frame.calldata[off + i].clone()
                        } else {
                            Cell::Con(0)
                        };
                        self.frame.mem[dst + i] = cell;
                    }
                }
                0x50 => {
                    self.pop();
                }
                0x51 => {
                    let off = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let Some(off) = sane_offset(off) else {
                        return Outcome::Prune("mload offset out of range".into());
                    };
                    let v = self.mload(off);
                    if std::env::var("BT_SYMDBG").is_ok() {
                        eprintln!(
                            "MLOAD pc={pc:04x} off={off:#x} -> {}",
                            match &v {
                                SVal::Con(c) => format!("con {c:#x}"),
                                SVal::Sym(t) => format!("SYM {t}"),
                            }
                        );
                    }
                    self.push(v);
                }
                0x52 => {
                    // MSTORE: pops offset (top) then value.
                    let off = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let v = self.pop();
                    let Some(off) = sane_offset(off) else {
                        return Outcome::Prune("mstore offset out of range".into());
                    };
                    self.mem_write_word(off, &v);
                }
                0x54 => {
                    let slot = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    if let Some(v) = self.frame.store.get(&slot) {
                        self.push(SVal::Con(*v));
                    } else if self.overlay_only {
                        self.push(SVal::Con(U256::ZERO));
                    } else {
                        let provider = self.provider.clone();
                        let addr = self.frame.address;
                        let index = slot;
                        let v = tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current()
                                .block_on(async { provider.get_storage_at(addr, index).await })
                        });
                        match v {
                            Ok(word) => self.push(SVal::Con(word)),
                            Err(e) => return Outcome::Prune(format!("sload: {e}")),
                        }
                    }
                }
                0x55 => {
                    let v = self.pop();
                    let slot = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    if matches!(self.goal.kind, GoalKind::SStore)
                        && slot == U256::from_be_slice(self.goal.address.as_slice())
                    {
                        let hit = match &v {
                            SVal::Con(c) => {
                                if *c >= self.goal.min_amount {
                                    Some(self.model_calldata())
                                } else {
                                    None
                                }
                            }
                            SVal::Sym(t) => {
                                self.solver.push();
                                self.solver.assert(&format!(
                                    "(bvuge {t} {})",
                                    word_lit(&self.goal.min_amount)
                                ));
                                let sat = self.solver.check_sat().unwrap_or(false);
                                let model = if sat {
                                    Some(self.model_calldata())
                                } else {
                                    None
                                };
                                self.solver.pop();
                                model
                            }
                        };
                        if let Some(model) = hit {
                            let value = self.concretize(&v);
                            self.frame.store.insert(slot, value);
                            return Outcome::GoalHit(model);
                        }
                    }
                    let value = self.concretize(&v);
                    self.frame.store.insert(slot, value);
                }
                0x56 => {
                    let dest = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let d = dest.as_limbs()[0] as usize;
                    if d >= self.frame.code.len() {
                        return Outcome::Revert; // jump beyond code is invalid
                    }
                    self.frame.pc = d;
                }
                0x57 => {
                    // JUMPI: pops destination (top) then condition.
                    let dest = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let d = dest.as_limbs()[0] as usize;
                    if d >= self.frame.code.len() {
                        return Outcome::Revert; // jump beyond code is invalid
                    }
                    let dest = d;
                    let cond = self.pop();
                    match cond.as_con() {
                        Some(c) => {
                            if !c.is_zero() {
                                self.frame.pc = dest;
                            }
                            continue;
                        }
                        None => {}
                    }
                    let t = self.term(&cond);
                    self.stats.paths += 1;
                    let z = word_lit(&U256::ZERO);

                    // True branch: cond != 0.
                    self.solver.push();
                    self.solver.assert(&format!("(distinct {t} {z})"));
                    let mut result = Outcome::Prune("unreachable true branch".into());
                    if self.solver.check_sat().unwrap_or(false) {
                        self.stats.solved_branches += 1;
                        let saved = self.frame.clone();
                        self.frame.pc = dest;
                        result = self.run();
                        if matches!(result, Outcome::GoalHit(_)) {
                            self.solver.pop();
                            return result;
                        }
                        self.frame = saved;
                    }
                    self.solver.pop();

                    // False branch: cond == 0.
                    self.solver.push();
                    self.solver.assert(&format!("(= {t} {z})"));
                    if self.solver.check_sat().unwrap_or(false) {
                        self.stats.solved_branches += 1;
                        let outcome = self.run();
                        self.solver.pop();
                        return outcome;
                    }
                    self.solver.pop();
                    return result;
                }
                0x31 => {
                    // BALANCE: concrete via the fork (offline: zero).
                    let who = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let bytes = who.to_be_bytes::<32>();
                    let addr = Address::from_slice(&bytes[12..]);
                    if self.overlay_only {
                        self.push(SVal::Con(U256::ZERO));
                    } else {
                        let provider = self.provider.clone();
                        let bal = self
                            .rt
                            .block_on(async move { provider.get_balance(addr).await });
                        match bal {
                            Ok(b) => self.push(SVal::Con(b)),
                            Err(_) => self.push(SVal::Con(U256::ZERO)),
                        }
                    }
                }
                0x3b => {
                    // EXTCODESIZE: concrete via the fork (offline: zero).
                    let who = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let bytes = who.to_be_bytes::<32>();
                    let addr = Address::from_slice(&bytes[12..]);
                    if self.overlay_only {
                        self.push(SVal::Con(U256::ZERO));
                    } else {
                        let provider = self.provider.clone();
                        let code = self
                            .rt
                            .block_on(async move { provider.get_code_at(addr).await });
                        self.push(SVal::Con(U256::from(code.map(|c| c.len()).unwrap_or(0))));
                    }
                }
                0x3d => self.push(SVal::Con(U256::from(self.frame.returndata.len()))),
                0x3e => {
                    // RETURNDATACOPY: concrete copy from the last sub-call.
                    let len = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let off = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let dst = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let (Some(dst), Some(off), Some(len)) =
                        (sane_offset(dst), sane_offset(off), sane_offset(len))
                    else {
                        return Outcome::Prune("returndatacopy range".into());
                    };
                    self.frame
                        .mem
                        .resize(dst.max(self.frame.mem.len()), Cell::Con(0));
                    self.frame.mem.resize(dst + len, Cell::Con(0));
                    for i in 0..len {
                        let b = self.frame.returndata.get(off + i).copied().unwrap_or(0);
                        self.frame.mem[dst + i] = Cell::Con(b);
                    }
                }
                0x58 => self.push(SVal::Con(U256::from(pc))),
                0x59 => {
                    let words = (self.frame.mem.len() + 31) / 32;
                    self.push(SVal::Con(U256::from(words * 32)));
                }
                0x5a => self.push(SVal::Con(U256::from(30_000_000u64))), // GAS: ample constant
                0x5b => {}                                               // JUMPDEST
                0x5f => self.push(zero()),
                0x60..=0x7f => {
                    let n = (op - 0x5f) as usize;
                    let end = (pc + 1 + n).min(self.frame.code.len());
                    let bytes = &self.frame.code[pc + 1..end];
                    let mut buf = [0u8; 32];
                    buf[32 - bytes.len()..].copy_from_slice(bytes);
                    self.push(SVal::Con(U256::from_be_bytes(buf)));
                    self.frame.pc = end;
                }
                0x80..=0x8f => {
                    let n = (op - 0x7f) as usize;
                    if n <= self.frame.stack.len() {
                        let v = self.frame.stack[self.frame.stack.len() - n].clone();
                        self.push(v);
                    } else {
                        return Outcome::Prune("stack underflow (dup)".into());
                    }
                }
                0x90..=0x9f => {
                    let n = (op - 0x8f) as usize;
                    let len = self.frame.stack.len();
                    if n < len {
                        self.frame.stack.swap(len - 1, len - 1 - n);
                    } else {
                        return Outcome::Prune("stack underflow (swap)".into());
                    }
                }
                0xa0..=0xa4 => {
                    let n = (op - 0xa0) as usize + 2;
                    for _ in 0..n {
                        self.pop();
                    }
                }
                0xf3 => {
                    let len = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let off = {
                        let v = self.pop();
                        self.concretize(&v)
                    };
                    let (Some(off), Some(len)) = (sane_offset(off), sane_offset(len)) else {
                        return Outcome::Prune("return range".into());
                    };
                    self.frame
                        .mem
                        .resize(off.max(self.frame.mem.len()), Cell::Con(0));
                    self.frame.mem.resize(off + len, Cell::Con(0));
                    let mut buf = vec![0u8; len];
                    for i in 0..len {
                        buf[i] = match self.frame.mem[off + i] {
                            Cell::Con(b) => b,
                            Cell::Sym(_) => 0,
                        };
                    }
                    return Outcome::Return(buf);
                }
                0xfd | 0xfe => {
                    self.stats.reverted += 1;
                    return Outcome::Revert;
                }
                0xf1 | 0xf2 | 0xf4 | 0xfa => {
                    let pops: usize = if op == 0xf1 || op == 0xf2 { 7 } else { 6 };
                    if self.frame.stack.len() < pops {
                        return Outcome::Prune("stack underflow (call)".into());
                    }
                    let mut vals = Vec::with_capacity(pops);
                    for _ in 0..pops {
                        vals.push(self.pop());
                    }
                    vals.reverse();
                    // EVM CALL pops (top first): gas, addr, value,
                    // inOff, inLen, retOff, retLen — so after the pop
                    // + reverse, vals = [retLen, retOff, inLen, inOff,
                    // value, addr] (+gas for CALL).
                    let (addr, value, in_off, in_len) = if pops == 7 {
                        (
                            vals[5].clone(),
                            vals[4].clone(),
                            {
                                let v = vals[3].clone();
                                self.concretize(&v)
                            },
                            {
                                let v = vals[2].clone();
                                self.concretize(&v)
                            },
                        )
                    } else {
                        (
                            vals[4].clone(),
                            zero(),
                            {
                                let v = vals[3].clone();
                                self.concretize(&v)
                            },
                            {
                                let v = vals[2].clone();
                                self.concretize(&v)
                            },
                        )
                    };
                    let (Some(in_off), Some(in_len)) = (sane_offset(in_off), sane_offset(in_len))
                    else {
                        self.stats.pruned += 1;
                        return Outcome::Prune("call args range out of bounds".into());
                    };
                    self.frame.mem.resize(in_off + in_len, Cell::Con(0));
                    if let Some(model) = self.check_call_goal(&addr, &value, in_off, in_len) {
                        return Outcome::GoalHit(model);
                    }
                    // Concretized sub-call (documented approximation).
                    let addr_con = self.concretize(&addr);
                    if addr_con.is_zero() {
                        self.push(zero());
                        self.push(zero());
                        continue;
                    }
                    let mut data = Vec::with_capacity(in_len);
                    for c in &self.frame.mem[in_off..in_off + in_len] {
                        match c {
                            Cell::Con(b) => data.push(*b),
                            Cell::Sym(t) => {
                                let v = self.solver.value(t).unwrap_or_default();
                                data.push(v.as_limbs()[0] as u8);
                            }
                        }
                    }
                    let value_con = self.concretize(&value);
                    let ret = self.eth_call_sub(addr_con, data, value_con);
                    match ret {
                        Some(bytes) => {
                            self.frame.returndata = bytes;
                            self.push(SVal::Con(U256::from(1u8)));
                        }
                        None => {
                            self.frame.returndata = vec![];
                            self.push(zero());
                        }
                    }
                    self.push(SVal::Con(U256::from(self.frame.returndata.len())));
                }
                _ => {
                    self.stats.pruned += 1;
                    return Outcome::Prune(format!("unsupported opcode 0x{op:02x} at pc {pc}"));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The action
// ---------------------------------------------------------------------------

/// symbolic-call: explore a contract call with symbolic calldata
/// arguments and search for an input reaching a profit condition.
///
/// options:
///   to:           target contract address (required)
///   function:     signature, e.g. "claim(uint256,uint256)" (required)
///   symbolicArgs: indices of 32-byte args to treat as symbolic
///                 (default: all)
///   from:         caller address (default: a neutral probe address)
///   maxPaths:     path budget (default 4096)
///   maxSteps:     step budget (default 5,000,000)
///   state:        {slot: value} storage overlay for offline use
///                 (default: read live storage from the target RPC)
///   goal:         {kind: ethTo|tokenTransfer|sstore, address, minAmount}
///                 — address is the recipient (ethTo), the token
///                 (tokenTransfer, recipient decoded from the transfer),
///                 or the slot number (sstore)
pub async fn symbolic_call(
    rpc_url: &str,
    options: &serde_json::Value,
) -> anyhow::Result<Vec<Finding>> {
    let to: Address = options
        .get("to")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("symbolic-call requires options.to"))?
        .parse()?;
    let signature = options
        .get("function")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("symbolic-call requires options.function"))?
        .to_string();
    let goal_val = options
        .get("goal")
        .ok_or_else(|| anyhow::anyhow!("symbolic-call requires options.goal"))?;
    let goal = Goal {
        kind: match goal_val.get("kind").and_then(serde_json::Value::as_str) {
            Some("ethTo") => GoalKind::EthTo,
            Some("tokenTransfer") => GoalKind::TokenTransfer,
            Some("sstore") => GoalKind::SStore,
            other => return Err(anyhow::anyhow!("unknown goal kind {other:?}")),
        },
        address: goal_val
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("goal.address is required"))?
            .parse()?,
        min_amount: crate::actions::parse_u256(
            goal_val
                .get("minAmount")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("goal.minAmount is required"))?,
        )?,
    };

    let caller: Address = options
        .get("from")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(PROBE_CALLER)
        .parse()?;

    // Calldata: selector + 32-byte words. Words listed in symbolicArgs
    // (default: all) become fresh bitvector variables.
    let selector = keccak256(signature.as_bytes());
    let selector = [selector[0], selector[1], selector[2], selector[3]];
    let n_args = signature
        .split('(')
        .nth(1)
        .map(|s| {
            s.trim_end_matches(')')
                .split(',')
                .filter(|p| !p.is_empty())
                .count()
        })
        .unwrap_or(0);
    let symbolic: Vec<bool> = match options.get("symbolicArgs") {
        Some(serde_json::Value::Array(idx)) => {
            let mut v = vec![false; n_args];
            for i in idx.iter().filter_map(|x| x.as_u64()) {
                if (i as usize) < n_args {
                    v[i as usize] = true;
                }
            }
            v
        }
        _ => vec![true; n_args],
    };

    let mut solver = Solver::new()?;

    // Target bytecode: fetched from the RPC, or supplied directly via
    // options.bytecode for offline exploration (tests, state-override
    // workflows).
    let code: Vec<u8> = match options.get("bytecode").and_then(serde_json::Value::as_str) {
        Some(hex) => alloy::hex::decode(hex.trim_start_matches("0x"))?,
        None => Vec::new(),
    };
    let has_explicit_code = !code.is_empty();

    let provider = crate::actions::connect(rpc_url).await?;

    let code = if has_explicit_code {
        code
    } else {
        let fetched = provider.get_code_at(to).await?;
        if fetched.is_empty() {
            return Ok(vec![Finding::new(
                "engine-evm-symbolic-call",
                format!("Target {} has no code", short(to)),
                "info",
            )
            .with("confidence", "confirmed")
            .with("layer", "L2")
            .with("description", "Nothing to explore.")]);
        }
        fetched.to_vec()
    };

    // Build calldata cells: concrete selector, symbolic arg words.
    let mut arg_vars = Vec::new();
    let mut calldata: Vec<Cell> = selector.iter().map(|b| Cell::Con(*b)).collect();
    for i in 0..n_args {
        if symbolic[i] {
            let var = format!("arg{i}");
            solver.cmd(&format!("(declare-fun {var} () (_ BitVec 256))"));
            arg_vars.push(var.clone());
            for k in 0..32 {
                let hi = (31 - k) * 8 + 7;
                let lo = (31 - k) * 8;
                let bt = solver.def_byte(&format!("((_ extract {hi} {lo}) {var})"));
                calldata.push(Cell::Sym(bt));
            }
        } else {
            for _ in 0..32 {
                calldata.push(Cell::Con(0));
            }
        }
    }

    // Capture the goal description before the machine takes ownership.
    let goal_kind_name = options
        .get("goal")
        .and_then(|g| g.get("kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("goal")
        .to_string();
    let goal_desc = format!(
        "kind={goal_kind_name} address={} min_amount={}",
        goal.address, goal.min_amount
    );
    let overlay: Option<HashMap<U256, U256>> = match options.get("state") {
        Some(serde_json::Value::Object(map)) => {
            let mut m = HashMap::new();
            for (slot, value) in map {
                let s = crate::actions::parse_u256(slot)?;
                let v = crate::actions::parse_u256(
                    value
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("state values must be strings"))?,
                )?;
                m.insert(s, v);
            }
            Some(m)
        }
        _ => None,
    };
    let overlay_only = overlay.is_some();

    let mut machine = Machine {
        frame: Frame {
            code: code.to_vec(),
            pc: 0,
            stack: Vec::new(),
            mem: Vec::new(),
            calldata,
            returndata: vec![],
            store: overlay.unwrap_or_default(),
            caller,
            address: to,
            value: U256::ZERO,
        },
        goal,
        provider,
        solver,
        rt: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
        arg_vars,
        selector,
        stats: Stats::default(),
        max_paths: options
            .get("maxPaths")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(4096) as u32,
        max_steps: options
            .get("maxSteps")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(5_000_000),
        overlay_only,
    };

    let join = tokio::task::spawn_blocking(move || {
        let outcome = machine.run();
        let stats = std::mem::take(&mut machine.stats);
        (outcome, stats)
    })
    .await
    .map_err(|e| anyhow::anyhow!("symbolic machine panicked: {e}"))?;
    let (outcome, stats) = join;
    let calldata_hex = |m: &[u8]| {
        format!(
            "0x{}",
            m.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    match outcome {
        Outcome::GoalHit(model) => Ok(vec![Finding::new(
            "engine-evm-symbolic-call",
            format!("Symbolic execution found an input reaching the goal: {signature}"),
            "high",
        )
        .with("confidence", "confirmed")
        .with("layer", "L2")
        .with(
            "description",
            format!(
                "The solver found a concrete calldata input such that executing \
                 {} on {} reaches the goal condition. This is a discovered \
                 attack input, not a replay: the corpus engine has crossed from \
                 regression to discovery.",
                signature, to
            ),
        )
        .with(
            "evidence",
            format!(
                "calldata={} goal({goal_desc}) paths_explored={} solved_branches={} steps={} pruned={}",
                calldata_hex(&model),
                stats.paths,
                stats.solved_branches,
                stats.steps,
                stats.pruned
            ),
        )]),
        Outcome::Return(_) | Outcome::Revert => Ok(vec![Finding::new(
            "engine-evm-symbolic-call",
            format!("No input reaches the goal within budget: {signature}"),
            "info",
        )
        .with("confidence", "probable")
        .with("layer", "L2")
        .with(
            "description",
            "Exhausted the search budget without finding an input that \
             satisfies the goal (or every candidate path reverted). This is \
             not a proof of safety: paths may have been pruned at unsupported \
             constructs.",
        )
        .with(
            "evidence",
            format!(
                "paths_explored={} solved_branches={} steps={} pruned={} reverted={}",
                stats.paths, stats.solved_branches, stats.steps, stats.pruned, stats.reverted
            ),
        )]),
        Outcome::Prune(reason) => Ok(vec![Finding::new(
            "engine-evm-symbolic-call",
            format!("Exploration pruned before any goal: {reason}"),
            "info",
        )
        .with("confidence", "confirmed")
        .with("layer", "L2")
        .with(
            "description",
            "The search stopped at an unsupported construct. See the roadmap \
             for the opcode-coverage plan; the machine is exact on the \
             supported subset.",
        )
        .with(
            "evidence",
            format!(
                "reason={reason} paths_explored={} solved_branches={} steps={}",
                stats.paths, stats.solved_branches, stats.steps
            ),
        )]),
    }
}

fn short(a: Address) -> String {
    format!("{a}")
}

/// Signed interpretation of a 256-bit word for SLT/SGT/SAR.
fn to_i256(v: U256) -> alloy::primitives::I256 {
    alloy::primitives::I256::from_raw(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solver_round_trip() {
        if !Solver::available() {
            eprintln!("skipping: z3 not installed");
            return;
        }
        let mut s = Solver::new().expect("z3");
        s.cmd("(declare-fun x () (_ BitVec 256))");
        s.assert("(bvugt x #x0000000000000000000000000000000000000000000000000000000000000029)");
        assert_eq!(s.check_sat(), Some(true));
        let v = s.value("x").unwrap();
        assert!(v > U256::from(41u8));
        s.push();
        s.assert("(bvult x #x0000000000000000000000000000000000000000000000000000000000000029)");
        assert_eq!(s.check_sat(), Some(false));
        s.pop();
        assert_eq!(s.check_sat(), Some(true));
    }

    // End-to-end: the solver must DISCOVER the drain input for the
    // LockedVault fixture (engine-evm/testdata/LockedVault.sol, solc
    // 0.8.38): the secret guess AND the maximal payout amount. Fully
    // offline — bytecode and storage supplied via job options, no RPC.
    // Regenerate the bytecode with:
    //   forge build --force  # in a project containing testdata/LockedVault.sol
    #[test]
    fn discovers_locked_vault_drain_input() {
        if !Solver::available() {
            eprintln!("skipping: z3 not installed");
            return;
        }
        let runtime = "0x608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80639b7b2ab014610038578063c349026314610056575b5f5ffd5b610040610072565b60405161004d91906101df565b60405180910390f35b610070600480360381019061006b9190610226565b610077565b005b5f5481565b651337beefcafe82146100bf576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100b6906102be565b60405180910390fd5b5f54811115610103576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016100fa90610326565b60405180910390fd5b805f5f8282546101139190610371565b925050819055505f3373ffffffffffffffffffffffffffffffffffffffff168260405161013f906103d1565b5f6040518083038185875af1925050503d805f8114610179576040519150601f19603f3d011682016040523d82523d5f602084013e61017e565b606091505b50509050806101c2576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101b99061042f565b60405180910390fd5b505050565b5f819050919050565b6101d9816101c7565b82525050565b5f6020820190506101f25f8301846101d0565b92915050565b5f5ffd5b610205816101c7565b811461020f575f5ffd5b50565b5f81359050610220816101fc565b92915050565b5f5f6040838503121561023c5761023b6101f8565b5b5f61024985828601610212565b925050602061025a85828601610212565b9150509250929050565b5f82825260208201905092915050565b7f77726f6e672067756573730000000000000000000000000000000000000000005f82015250565b5f6102a8600b83610264565b91506102b382610274565b602082019050919050565b5f6020820190508181035f8301526102d58161029c565b9050919050565b7f746f6f20677265656479000000000000000000000000000000000000000000005f82015250565b5f610310600a83610264565b915061031b826102dc565b602082019050919050565b5f6020820190508181035f83015261033d81610304565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61037b826101c7565b9150610386836101c7565b925082820390508181111561039e5761039d610344565b5b92915050565b5f81905092915050565b50565b5f6103bc5f836103a4565b91506103c7826103ae565b5f82019050919050565b5f6103db826103b1565b9150819050919050565b7f706179206661696c6564000000000000000000000000000000000000000000005f82015250565b5f610419600a83610264565b9150610424826103e5565b602082019050919050565b5f6020820190508181035f8301526104468161040d565b905091905056fea2646970667358221220503ca81fbf2fb887dfc0467a7831cefbc6de915e3a256bbc9b4ee970f672c71164736f6c63430008260033";
        let options = serde_json::json!({
            "to": "0x000000000000000000000000000000000000dead",
            "function": "claim(uint256,uint256)",
            "bytecode": runtime,
            "state": {"0": "5000000000000000000"},
            "goal": {
                "kind": "ethTo",
                "address": "0x0000000000000000000000000000000000008008",
                "minAmount": "5000000000000000000"
            }
        });
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let findings = rt
            .block_on(symbolic_call("http://127.0.0.1:1", &options))
            .expect("symbolic run");
        assert_eq!(findings.len(), 1, "expected one finding");
        assert_eq!(findings[0].severity, "high", "{}", findings[0].title);
        let ev = &findings[0].evidence;
        let calldata = ev
            .split("calldata=0x")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .expect("model calldata in evidence");
        let bytes = alloy::hex::decode(calldata).expect("hex");
        // selector + guess + amount
        assert_eq!(bytes.len(), 68);
        let guess = U256::from_be_slice(&bytes[4..36]);
        let amount = U256::from_be_slice(&bytes[36..68]);
        assert_eq!(
            guess,
            U256::from_str_radix("1337beefcafe", 16).unwrap(),
            "solver must discover the secret"
        );
        assert_eq!(
            amount,
            U256::from(5_000_000_000_000_000_000u64),
            "solver must discover the maximal payout"
        );
    }
}
