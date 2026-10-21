//! Cumplimiento REAL de ejecución firmada sin BPF-LSM: seccomp
//! user-notification (`SECCOMP_RET_USER_NOTIF`) + Landlock. v0.3.
//!
//! ## Modelo
//! 1. `execve` con ruta se **niega** siempre.
//! 2. Solo se permite `execveat(fd, "", AT_EMPTY_PATH)`.
//! 3. El lanzador crea un `memfd` **sellado**
//!    (`F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_SEAL`); el hijo hereda
//!    el fd, instala el filtro + Landlock y hace el `execveat`. El supervisor
//!    re-verifica el contenido del fd en el gate. Memfd sellado ⇒ sin TOCTOU.
//! 4. `mmap`/`mprotect`/`pkey_mprotect` con `PROT_EXEC` se **niegan** siempre.
//!    Contrato: ejecutables **estáticos** (sin `PT_INTERP`).
//! 5. Scripts (`#!`), `PT_INTERP`, `PT_GNU_STACK` X → rechazo en el gate.
//! 6. arch ≠ x86-64 / x32 → `KILL`. `personality(RIE)`, `mremap`/`remap_file_pages`
//!    de VMA X, `ptrace`, `process_vm_writev`, `userfaultfd`, `seccomp`,
//!    `prctl(PR_SET_SECCOMP)`, `io_uring_setup`, `shmat(SHM_EXEC)` → deny.
//! 7. Landlock niega `WRITE_FILE` bajo `/proc` (cierra `/proc/<pid>/mem`).
//!
//! Sin root (`NO_NEW_PRIVS`). Fuera de alcance: ver LIMITES.md.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use libc::{c_void, sock_filter, sock_fprog};

use crate::verify::{verify_elf, ProofVerifier};

// --- syscalls x86-64 que vigilamos ---
pub const SYS_MMAP: u32 = 9;
pub const SYS_MPROTECT: u32 = 10;
pub const SYS_MREMAP: u32 = 25;
pub const SYS_EXECVE: u32 = 59;
pub const SYS_PTRACE: u32 = 101;
pub const SYS_PERSONALITY: u32 = 135;
pub const SYS_REMAP_FILE_PAGES: u32 = 216;
pub const SYS_PROCESS_VM_WRITEV: u32 = 311;
pub const SYS_EXECVEAT: u32 = 322;
pub const SYS_USERFAULTFD: u32 = 323;
pub const SYS_PKEY_MPROTECT: u32 = 329;
// Familia de escritura: se vigilan para negar escrituras a `/proc/<pid>/mem`
// (reescribir el propio `.text` r-x por FOLL_FORCE sortea el W^X).
pub const SYS_WRITE: u32 = 1;
pub const SYS_PWRITE64: u32 = 18;
pub const SYS_WRITEV: u32 = 20;
pub const SYS_PWRITEV: u32 = 296;
pub const SYS_PWRITEV2: u32 = 328;
pub const SYS_SHMAT: u32 = 30;
pub const SYS_PRCTL: u32 = 157;
pub const SYS_SECCOMP: u32 = 317;
pub const SYS_IO_URING_SETUP: u32 = 425;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// Bit de syscall x32 (`__X32_SYSCALL_BIT`): mismo arch token que x86-64.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// `READ_IMPLIES_EXEC` de `<linux/personality.h>`.
pub const READ_IMPLIES_EXEC: u64 = 0x0040_0000;
const PR_SET_SECCOMP: u64 = 22;
const SHM_EXEC: u64 = 0o100000;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
/// Debe ser `1 << 3` (kernel). `1 << 4` es `TSYNC_ESRCH` y NO crea listener.
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// --- ioctl SECCOMP_IOCTL_NOTIF_* calculados a mano (_IOC) ---
const IOC_WRITE: libc::c_ulong = 1;
const IOC_READ: libc::c_ulong = 2;
const fn ioc(dir: libc::c_ulong, ty: libc::c_ulong, nr: libc::c_ulong, size: libc::c_ulong) -> libc::c_ulong {
    (dir << 30) | (ty << 8) | nr | (size << 16)
}
const SECCOMP_IOC_MAGIC: libc::c_ulong = b'!' as libc::c_ulong;
fn notif_recv_ioctl() -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, SECCOMP_IOC_MAGIC, 0, std::mem::size_of::<SeccompNotif>() as libc::c_ulong)
}
fn notif_send_ioctl() -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, SECCOMP_IOC_MAGIC, 1, std::mem::size_of::<SeccompNotifResp>() as libc::c_ulong)
}
fn notif_id_valid_ioctl() -> libc::c_ulong {
    ioc(IOC_WRITE, SECCOMP_IOC_MAGIC, 2, std::mem::size_of::<u64>() as libc::c_ulong)
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Syscalls que se notifican al supervisor (él decide).
pub const NOTIFIED: [u32; 20] = [
    SYS_MMAP,
    SYS_MPROTECT,
    SYS_PKEY_MPROTECT,
    SYS_EXECVE,
    SYS_EXECVEAT,
    SYS_PERSONALITY,
    SYS_MREMAP,
    SYS_REMAP_FILE_PAGES,
    SYS_PTRACE,
    SYS_PROCESS_VM_WRITEV,
    SYS_USERFAULTFD,
    SYS_WRITE,
    SYS_PWRITE64,
    SYS_WRITEV,
    SYS_PWRITEV,
    SYS_PWRITEV2,
    SYS_SHMAT,
    SYS_PRCTL,
    SYS_SECCOMP,
    SYS_IO_URING_SETUP,
];

/// Programa cBPF (v0.2).
///
/// - `arch != AUDIT_ARCH_X86_64` (p. ej. i386 por `int $0x80`) → `KILL_PROCESS`.
/// - `nr & __X32_SYSCALL_BIT` (x32) → `KILL_PROCESS`.
/// - Cada syscall de [`NOTIFIED`] → `USER_NOTIF`.
/// - Resto → `ALLOW`.
///
/// Los saltos de cBPF son solo hacia adelante: los `RET` van al final.
pub fn filter_program() -> Vec<sock_filter> {
    let st = |code: u16, k: u32| sock_filter { code, jt: 0, jf: 0, k };
    let jmp = |code: u16, k: u32, jt: u8, jf: u8| sock_filter { code, jt, jf, k };
    const LD_W_ABS: u16 = 0x20;
    const JMP_JEQ_K: u16 = 0x15;
    const JMP_JSET_K: u16 = 0x45;
    const RET_K: u16 = 0x06;
    const OFF_ARCH: u32 = 4;
    const OFF_NR: u32 = 0;

    let n = NOTIFIED.len();
    // Índices: 0 ld arch | 1 jeq arch | 2 ld nr | 3 jset x32 | 4..4+n jeq nr
    //          4+n ret ALLOW | 5+n ret KILL | 6+n ret NOTIF
    let i_allow = 4 + n;
    let i_kill = i_allow + 1;
    let i_notif = i_allow + 2;
    let off = |from: usize, to: usize| -> u8 { (to - from - 1) as u8 };

    let mut p = Vec::with_capacity(i_notif + 1);
    p.push(st(LD_W_ABS, OFF_ARCH));
    p.push(jmp(JMP_JEQ_K, AUDIT_ARCH_X86_64, 0, off(1, i_kill)));
    p.push(st(LD_W_ABS, OFF_NR));
    p.push(jmp(JMP_JSET_K, X32_SYSCALL_BIT, off(3, i_kill), 0));
    for (j, nr) in NOTIFIED.iter().enumerate() {
        let idx = 4 + j;
        p.push(jmp(JMP_JEQ_K, *nr, off(idx, i_notif), 0));
    }
    p.push(st(RET_K, SECCOMP_RET_ALLOW));
    p.push(st(RET_K, SECCOMP_RET_KILL_PROCESS));
    p.push(st(RET_K, SECCOMP_RET_USER_NOTIF));
    p
}

/// Instala el filtro en el proceso actual y devuelve el fd del listener.
pub fn install_listener() -> io::Result<OwnedFd> {
    let prog = filter_program();
    let fprog = sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut sock_filter };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const _ as *const c_void,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd as RawFd))
    }
}

/// Manda un fd por un socket AF_UNIX con `SCM_RIGHTS`. Solo buffers de pila.
pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut c_void, iov_len: 1 };
    const SPACE: usize = 64;
    let mut cbuf = [0u8; SPACE];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsg) as *mut RawFd, 1);
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Recibe un fd mandado con [`send_fd`].
pub fn recv_fd(sock: RawFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut c_void, iov_len: 1 };
    let mut cbuf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cbuf.len() as _;
    unsafe {
        let n = libc::recvmsg(sock, &mut msg, 0);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no llegó ningún fd"));
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg) as *const RawFd, &mut fd, 1);
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Pedido notificado. `prot`/`flags`/`fd`/`addr`/`len` se interpretan para
/// `mmap`/`mprotect`/`pkey_mprotect`; `args` trae los 6 argumentos crudos.
#[derive(Debug, Clone, Copy)]
pub struct ExecRequest {
    pub pid: u32,
    pub nr: i32,
    pub prot: u64,
    pub flags: u64,
    pub fd: i32,
    pub addr: u64,
    pub len: u64,
    pub args: [u64; 6],
}

impl ExecRequest {
    pub fn wants_exec(&self) -> bool {
        self.prot & libc::PROT_EXEC as u64 != 0
    }
    pub fn is_file_backed_mmap(&self) -> bool {
        self.nr == SYS_MMAP as i32 && self.fd >= 0 && self.flags & libc::MAP_ANONYMOUS as u64 == 0
    }
    pub fn is_anonymous_mmap(&self) -> bool {
        self.nr == SYS_MMAP as i32 && (self.fd < 0 || self.flags & libc::MAP_ANONYMOUS as u64 != 0)
    }
}

fn parse(data: &SeccompData, pid: u32) -> ExecRequest {
    let a = data.args;
    let nr = data.nr;
    // mmap(addr,len,prot,flags,fd,off); mprotect/pkey_mprotect(addr,len,prot[,pkey])
    let (prot, flags, fd) = if nr == SYS_MMAP as i32 {
        (a[2], a[3], a[4] as i32)
    } else if nr == SYS_MPROTECT as i32 || nr == SYS_PKEY_MPROTECT as i32 {
        (a[2], 0, -1)
    } else {
        (0, 0, -1)
    };
    ExecRequest { pid, nr, prot, flags, fd, addr: a[0], len: a[1], args: a }
}

/// Veredicto del supervisor para una notificación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Dejar correr el syscall real (CONTINUE).
    Continue,
    /// Devolver este errno sin ejecutar el syscall.
    Deny(i32),
}

/// Ruta del `readlink` de `/proc/<pid>/fd/<fd>` (solo diagnóstico).
pub fn backing_path(pid: u32, fd: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
}

/// Lee **todos** los bytes del archivo abierto en el fd `fd` del proceso `pid`.
pub fn read_via_proc_fd(pid: u32, fd: i32) -> io::Result<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/fd/{fd}"))
}

/// Lee el archivo **realmente mapeado** en la VMA `[start,end)` vía
/// `/proc/<pid>/map_files/`. Sigue al inodo del mapeo aunque la ruta se haya
/// renombrado (cierra el TOCTOU de ruta de `mprotect`).
#[allow(dead_code)]
pub fn read_via_map_files(pid: u32, start: u64, end: u64) -> io::Result<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/map_files/{start:x}-{end:x}"))
}

/// Entrada de `/proc/<pid>/maps` que cubre `addr`.
#[derive(Debug, Clone)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub path: Option<PathBuf>,
}

impl MapEntry {
    pub fn is_writable(&self) -> bool {
        self.perms.as_bytes().get(1) == Some(&b'w')
    }
    pub fn is_exec(&self) -> bool {
        self.perms.as_bytes().get(2) == Some(&b'x')
    }
}

/// Busca en `/proc/<pid>/maps` la VMA que contiene `addr`.
pub fn find_vma(pid: u32, addr: u64) -> io::Result<Option<MapEntry>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else { continue };
        let Some((a, b)) = range.split_once('-') else { continue };
        let start = u64::from_str_radix(a, 16).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let end = u64::from_str_radix(b, 16).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if addr < start || addr >= end {
            continue;
        }
        let perms = parts.next().unwrap_or("").to_string();
        let offset = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let _dev = parts.next();
        let _inode = parts.next();
        let path = parts.next().and_then(|p| if p.starts_with('[') { None } else { Some(PathBuf::from(p)) });
        return Ok(Some(MapEntry { start, end, perms, offset, path }));
    }
    Ok(None)
}

/// ¿El string C en `ptr` del proceso `pid` está vacío? Ante error, `false`
/// (el llamador niega).
fn child_cstr_is_empty(pid: u32, ptr: u64) -> bool {
    if ptr == 0 {
        return false;
    }
    let Ok(f) = std::fs::File::open(format!("/proc/{pid}/mem")) else { return false };
    let mut b = [0xffu8; 1];
    matches!(f.read_at(&mut b, ptr), Ok(1)) && b[0] == 0
}

/// Gate de exec: solo `execveat(fd, "", AT_EMPTY_PATH)` con contenido firmado
/// x86-64. Rechaza scripts `#!` (no son ELF firmado).
fn policy_execveat(req: &ExecRequest, verifiers: &[&dyn ProofVerifier]) -> Verdict {
    let dirfd = req.args[0] as i32;
    let path_ptr = req.args[1];
    let flags = req.args[4];
    if flags & libc::AT_EMPTY_PATH as u64 == 0 {
        return Verdict::Deny(libc::EACCES);
    }
    if !child_cstr_is_empty(req.pid, path_ptr) {
        return Verdict::Deny(libc::EACCES);
    }
    let Ok(bytes) = read_via_proc_fd(req.pid, dirfd) else {
        return Verdict::Deny(libc::EACCES);
    };
    if elf_exec_gate(&bytes).is_err() {
        return Verdict::Deny(libc::EACCES);
    }
    match verify_elf(bytes, verifiers) {
        Ok(_) => Verdict::Continue,
        Err(_) => Verdict::Deny(libc::EACCES),
    }
}

/// Chequeos estructurales del ELF en el gate de exec (antes de la firma).
pub fn elf_exec_gate(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.starts_with(b"#!") {
        return Err("script");
    }
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 {
        return Err("no ELF64");
    }
    if u16::from_le_bytes([bytes[18], bytes[19]]) != 62 {
        return Err("no x86-64");
    }
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
    if phentsize < 56 || phnum == 0 {
        return Err("phdrs");
    }
    let Some(end) = phoff.checked_add(phentsize.saturating_mul(phnum)) else {
        return Err("phdrs overflow");
    };
    let Some(phdrs) = bytes.get(phoff..end) else {
        return Err("phdrs oob");
    };
    for ph in phdrs.chunks(phentsize) {
        if ph.len() < 8 {
            continue;
        }
        let p_type = u32::from_le_bytes(ph[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(ph[4..8].try_into().unwrap());
        if p_type == 3 {
            return Err("PT_INTERP");
        }
        if p_type == 1 && (flags & 1) != 0 && (flags & 2) != 0 {
            return Err("PT_LOAD W+X");
        }
        if p_type == 0x6474e551 && (flags & 1) != 0 {
            return Err("PT_GNU_STACK X");
        }
    }
    Ok(())
}
fn policy_mmap(req: &ExecRequest, _verifiers: &[&dyn ProofVerifier]) -> Verdict {
    if !req.wants_exec() {
        return Verdict::Continue;
    }
    // W^X estricto: NINGÚN `mmap(PROT_EXEC)` de usuario se concede. El único
    // código ejecutable nace del `execveat` del memfd sellado. Un CONTINUE
    // sobre file-backed sería TOCTOU (archivo mutable por un 2º fd).
    Verdict::Deny(libc::EPERM)
}

fn policy_mprotect(req: &ExecRequest, _verifiers: &[&dyn ProofVerifier]) -> Verdict {
    if !req.wants_exec() {
        return Verdict::Continue;
    }
    // Nunca se puede volver ejecutable una página ya mapeada.
    Verdict::Deny(libc::EPERM)
}

/// ¿La ruta canónica es `/proc/<pid|self|thread-self>/[task/<tid>/]mem`?
/// El `readlink` de un fd da la ruta canónica aunque se haya abierto por un
/// symlink, así que el chequeo es robusto a trucos de enlace.
pub fn is_proc_mem_path(p: &Path) -> bool {
    let c: Vec<&OsStr> = p.iter().collect();
    let as_str = |o: &OsStr| o.to_str().map(|s| s.to_string());
    let is_pid = |o: &OsStr| matches!(as_str(o).as_deref(), Some("self") | Some("thread-self"))
        || o.to_str().map(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false);
    // ["/", "proc", <pid>, "mem"]  o  ["/", "proc", <pid>, "task", <tid>, "mem"]
    match c.as_slice() {
        [root, proc, pid, mem]
            if *root == OsStr::new("/") && *proc == OsStr::new("proc") && *mem == OsStr::new("mem") =>
        {
            is_pid(pid)
        }
        [root, proc, pid, task, tid, mem]
            if *root == OsStr::new("/")
                && *proc == OsStr::new("proc")
                && *task == OsStr::new("task")
                && *mem == OsStr::new("mem") =>
        {
            is_pid(pid) && is_pid(tid)
        }
        _ => false,
    }
}

/// Niega escrituras cuyo fd destino resuelve a `/proc/<pid>/mem` (reescribir el
/// propio `.text` r-x por FOLL_FORCE). Cualquier otro destino (stdout, pipes,
/// archivos de datos) pasa. Ante error de `readlink` (fd sin ruta: pipe/socket)
/// se permite: no es la superficie peligrosa.
pub fn policy_write(req: &ExecRequest) -> Verdict {
    let fd = req.args[0] as i64;
    if fd < 0 {
        return Verdict::Continue;
    }
    match backing_path(req.pid, fd as i32) {
        Ok(p) if is_proc_mem_path(&p) => Verdict::Deny(libc::EACCES),
        _ => Verdict::Continue,
    }
}

/// Política completa v0.2 (ver doc del módulo).
pub fn policy_verify_fnbr(req: &ExecRequest, verifiers: &[&dyn ProofVerifier]) -> Verdict {
    let nr = req.nr as u32;
    match nr {
        SYS_EXECVE => Verdict::Deny(libc::EACCES),
        SYS_EXECVEAT => policy_execveat(req, verifiers),
        SYS_MMAP => policy_mmap(req, verifiers),
        SYS_MPROTECT | SYS_PKEY_MPROTECT => policy_mprotect(req, verifiers),
        SYS_PERSONALITY => {
            let p = req.args[0];
            if p != 0xffff_ffff && p != u64::MAX && p & READ_IMPLIES_EXEC != 0 {
                Verdict::Deny(libc::EPERM)
            } else {
                Verdict::Continue
            }
        }
        SYS_MREMAP | SYS_REMAP_FILE_PAGES => match find_vma(req.pid, req.args[0]) {
            Ok(Some(v)) if v.is_exec() => Verdict::Deny(libc::EPERM),
            Ok(_) => Verdict::Continue,
            Err(_) => Verdict::Deny(libc::EPERM),
        },
        SYS_PTRACE | SYS_PROCESS_VM_WRITEV | SYS_USERFAULTFD | SYS_SECCOMP | SYS_IO_URING_SETUP => {
            Verdict::Deny(libc::EPERM)
        }
        SYS_PRCTL => {
            if req.args[0] == PR_SET_SECCOMP {
                Verdict::Deny(libc::EPERM)
            } else {
                Verdict::Continue
            }
        }
        SYS_SHMAT => {
            if req.args[2] & SHM_EXEC != 0 {
                Verdict::Deny(libc::EPERM)
            } else {
                Verdict::Continue
            }
        }
        SYS_WRITE | SYS_PWRITE64 | SYS_WRITEV | SYS_PWRITEV | SYS_PWRITEV2 => policy_write(req),
        _ => Verdict::Continue,
    }
}

/// Atiende notificaciones hasta que `keep_going()` sea falso y no haya más
/// pendientes. `policy` decide **cada** syscall notificado.
pub fn supervise<P, K>(listener: &OwnedFd, mut policy: P, keep_going: K) -> io::Result<u64>
where
    P: FnMut(&ExecRequest) -> Verdict,
    K: Fn() -> bool,
{
    let lfd = listener.as_raw_fd();
    let recv = notif_recv_ioctl();
    let send = notif_send_ioctl();
    let idv = notif_id_valid_ioctl();
    let mut handled = 0u64;

    loop {
        let mut pfd = libc::pollfd { fd: lfd, events: libc::POLLIN, revents: 0 };
        let pr = unsafe { libc::poll(&mut pfd, 1, 100) };
        if pr < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        if pr == 0 {
            if !keep_going() {
                return Ok(handled);
            }
            continue;
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 && pfd.revents & libc::POLLIN == 0 {
            // Todos los procesos con el filtro terminaron.
            if !keep_going() {
                return Ok(handled);
            }
            continue;
        }

        let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(lfd, recv, &mut req) } != 0 {
            let e = io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::EINTR)) {
                if !keep_going() {
                    return Ok(handled);
                }
                continue;
            }
            return Err(e);
        }

        let er = parse(&req.data, req.pid);
        let verdict = policy(&er);

        let mut resp = SeccompNotifResp { id: req.id, val: 0, error: 0, flags: 0 };
        match verdict {
            Verdict::Continue => resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            Verdict::Deny(errno) => resp.error = -errno,
        }
        if unsafe { libc::ioctl(lfd, idv, &req.id) } != 0 {
            continue;
        }
        if unsafe { libc::ioctl(lfd, send, &resp) } != 0 {
            let e = io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::ENOENT)) {
                continue;
            }
            return Err(e);
        }
        if er.wants_exec() || matches!(er.nr as u32, SYS_EXECVE | SYS_EXECVEAT) {
            handled += 1;
        }
    }
}


// --- Landlock: niega WRITE_FILE bajo /proc (cierra /proc/<pid>/mem) ---

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Instala Landlock: permite `WRITE_FILE` en entradas de `/` excepto `proc`.
pub fn install_landlock_deny_proc_write() -> io::Result<()> {
    let attr = LandlockRulesetAttr { handled_access_fs: LANDLOCK_ACCESS_FS_WRITE_FILE };
    let rf = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const _ as *const c_void,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if rf < 0 {
        return Err(io::Error::last_os_error());
    }
    let rf = rf as RawFd;
    for ent in std::fs::read_dir("/")? {
        let ent = ent?;
        if ent.file_name() == OsStr::new("proc") {
            continue;
        }
        let path = ent.path();
        let cpath = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            continue;
        }
        let pb = LandlockPathBeneathAttr {
            allowed_access: LANDLOCK_ACCESS_FS_WRITE_FILE,
            parent_fd: fd,
        };
        let _ = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                rf as libc::c_long,
                LANDLOCK_RULE_PATH_BENEATH as libc::c_long,
                &pb as *const _ as *const c_void,
                0u32,
            )
        };
        unsafe { libc::close(fd) };
    }
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, rf as libc::c_long, 0u32) };
    unsafe { libc::close(rf) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Crea un `memfd` con `bytes` y lo sella contra escritura, crecimiento,
/// achique y nuevos sellos. Lo que se ejecute desde ahí es inmutable.
pub fn create_sealed_memfd(bytes: &[u8]) -> io::Result<OwnedFd> {
    let name = CString::new("fnbr-verified").expect("nombre sin NUL");
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut off = 0usize;
    while off < bytes.len() {
        let n = unsafe { libc::write(fd, bytes[off..].as_ptr() as *const c_void, bytes.len() - off) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        off += n as usize;
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Sellos actuales de un fd (`F_GET_SEALS`).
pub fn get_seals(fd: RawFd) -> io::Result<i32> {
    let r = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

extern "C" {
    static environ: *const *const libc::c_char;
}

/// Lanza `program`+`args` bajo el filtro seccomp y aplica `policy` a cada
/// syscall notificado. Sin privilegios (`NO_NEW_PRIVS`).
///
/// v0.2: el padre copia `program` a un `memfd` sellado; el hijo instala el
/// filtro y hace `execveat(memfd, "", AT_EMPTY_PATH)`. Ese exec también pasa
/// por `policy` (con [`policy_verify_fnbr`], el contenido debe verificar).
pub fn run_supervised(
    program: &Path,
    args: &[impl AsRef<OsStr>],
    mut policy: impl FnMut(&ExecRequest) -> Verdict,
) -> io::Result<(ExitStatus, u64)> {
    let bytes = std::fs::read(program)?;
    let mfd = create_sealed_memfd(&bytes)?;
    let mfd_raw = mfd.as_raw_fd();

    // argv armado antes del fork (el hijo no asigna memoria).
    let prog = CString::new(program.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL en la ruta"))?;
    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(prog);
    for a in args {
        c_args.push(
            CString::new(a.as_ref().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL en argumento"))?,
        );
    }
    let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let empty: &[u8; 1] = b"\0";

    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (parent_sock, child_sock) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // --- hijo ---
        drop(parent_sock);
        let listener = match install_listener() {
            Ok(l) => l,
            Err(_) => unsafe { libc::_exit(90) },
        };
        if send_fd(child_sock.as_raw_fd(), listener.as_raw_fd()).is_err() {
            unsafe { libc::_exit(91) };
        }
        drop(listener);
        drop(child_sock);
        if install_landlock_deny_proc_write().is_err() {
            unsafe { libc::_exit(94) };
        }
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                mfd_raw as libc::c_long,
                empty.as_ptr(),
                ptrs.as_ptr(),
                environ,
                libc::AT_EMPTY_PATH as libc::c_long,
            );
            libc::_exit(93);
        }
    }

    // --- padre ---
    drop(child_sock);
    let listener = recv_fd(parent_sock.as_raw_fd())?;
    let _keep = parent_sock;
    let _keep_mfd = mfd;

    let child_pid = pid;
    let reaped = std::sync::Mutex::new(None::<i32>);
    let handled = supervise(&listener, &mut policy, || {
        let mut guard = reaped.lock().unwrap();
        if guard.is_some() {
            return false;
        }
        let mut st = 0;
        let r = unsafe { libc::waitpid(child_pid, &mut st, libc::WNOHANG) };
        if r == child_pid {
            *guard = Some(st);
            return false;
        }
        true
    })?;

    let status = {
        let guard = reaped.lock().unwrap();
        if let Some(st) = *guard {
            st
        } else {
            drop(guard);
            let mut st = 0;
            if unsafe { libc::waitpid(child_pid, &mut st, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            st
        }
    };
    use std::os::unix::process::ExitStatusExt;
    Ok((ExitStatus::from_raw(status), handled))
}

/// Atajo: supervisa con [`policy_verify_fnbr`].
pub fn run_supervised_verify(
    program: &Path,
    args: &[impl AsRef<OsStr>],
    verifiers: &[&dyn ProofVerifier],
) -> io::Result<(ExitStatus, u64)> {
    run_supervised(program, args, |req| policy_verify_fnbr(req, verifiers))
}

/// Expone el listener crudo para tests que quieran controlar el bucle a mano.
#[allow(dead_code)]
pub(crate) fn into_raw_listener_for_tests(fd: OwnedFd) -> RawFd {
    fd.into_raw_fd()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_has_expected_shape() {
        let p = filter_program();
        let n = NOTIFIED.len();
        assert_eq!(p.len(), 4 + n + 3);
        assert_eq!(p[4 + n].k, SECCOMP_RET_ALLOW);
        assert_eq!(p[5 + n].k, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(p[6 + n].k, SECCOMP_RET_USER_NOTIF);
        // arch ≠ x86-64 salta a KILL; x32 salta a KILL; cada nr salta a NOTIF
        assert_eq!(1 + 1 + p[1].jf as usize, 5 + n);
        assert_eq!(3 + 1 + p[3].jt as usize, 5 + n);
        for j in 0..n {
            assert_eq!(4 + j + 1 + p[4 + j].jt as usize, 6 + n);
        }
        assert_eq!(SECCOMP_FILTER_FLAG_NEW_LISTENER, 1 << 3);
    }

    #[test]
    fn ioctl_numbers_match_known_constants() {
        assert_eq!(notif_recv_ioctl(), 0xC050_2100, "RECV");
        assert_eq!(notif_send_ioctl(), 0xC018_2101, "SEND");
        assert_eq!(notif_id_valid_ioctl(), 0x4008_2102, "ID_VALID");
    }

    #[test]
    fn struct_sizes_are_abi_stable() {
        assert_eq!(std::mem::size_of::<SeccompData>(), 64);
        assert_eq!(std::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(std::mem::size_of::<SeccompNotifResp>(), 24);
    }

    #[test]
    fn exec_request_classification() {
        let data = SeccompData {
            nr: SYS_MMAP as i32,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0,
            args: [0, 4096, libc::PROT_EXEC as u64 | libc::PROT_READ as u64, libc::MAP_PRIVATE as u64, 7, 0],
        };
        let er = parse(&data, 123);
        assert!(er.wants_exec());
        assert!(er.is_file_backed_mmap());
        assert!(!er.is_anonymous_mmap());
        assert_eq!(er.fd, 7);
    }

    #[test]
    fn anonymous_exec_classified() {
        let data = SeccompData {
            nr: SYS_MMAP as i32,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0,
            args: [
                0,
                4096,
                (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        };
        let er = parse(&data, 1);
        assert!(er.wants_exec());
        assert!(er.is_anonymous_mmap());
    }

    #[test]
    fn pkey_mprotect_parsed_as_mprotect() {
        let data = SeccompData {
            nr: SYS_PKEY_MPROTECT as i32,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0,
            args: [0x1000, 4096, (libc::PROT_READ | libc::PROT_EXEC) as u64, u64::MAX, 0, 0],
        };
        let er = parse(&data, 1);
        assert!(er.wants_exec());
    }

    #[test]
    fn execve_with_path_always_denied() {
        let req = ExecRequest { pid: 1, nr: SYS_EXECVE as i32, prot: 0, flags: 0, fd: -1, addr: 0, len: 0, args: [0; 6] };
        assert_eq!(policy_verify_fnbr(&req, &[]), Verdict::Deny(libc::EACCES));
    }

    #[test]
    fn personality_rie_denied_query_allowed() {
        let mk = |a0: u64| ExecRequest {
            pid: 1, nr: SYS_PERSONALITY as i32, prot: 0, flags: 0, fd: -1, addr: a0, len: 0, args: [a0, 0, 0, 0, 0, 0],
        };
        assert_eq!(policy_verify_fnbr(&mk(READ_IMPLIES_EXEC), &[]), Verdict::Deny(libc::EPERM));
        assert_eq!(policy_verify_fnbr(&mk(0xffff_ffff), &[]), Verdict::Continue);
        assert_eq!(policy_verify_fnbr(&mk(0), &[]), Verdict::Continue);
    }

    #[test]
    fn sealed_memfd_rejects_writes() {
        let fd = create_sealed_memfd(b"\x7fELF-test").unwrap();
        let seals = get_seals(fd.as_raw_fd()).unwrap();
        let want = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(seals & want, want);
        let n = unsafe { libc::pwrite(fd.as_raw_fd(), b"X".as_ptr() as *const c_void, 1, 0) };
        assert_eq!(n, -1, "escritura sobre memfd sellado debe fallar");
    }
}
