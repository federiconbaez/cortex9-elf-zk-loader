//! Cumplimiento REAL de `PROT_EXEC` sin BPF-LSM, usando seccomp
//! user-notification (`SECCOMP_RET_USER_NOTIF`).
//!
//! Idea: el proceso supervisado instala un filtro seccomp que, en `mmap` y
//! `mprotect`, en vez de ejecutar el syscall, **notifica** a un supervisor y
//! espera su veredicto. El supervisor (otro proceso, sin filtro) inspecciona
//! la notificación: si se pide `PROT_EXEC` sobre un archivo, verifica su
//! `.fnbr.sig` leyendo los bytes vía `/proc/<pid>/fd/<fd>` (mismo open file);
//! permite (`CONTINUE`) solo si la firma es válida, y si no devuelve `EPERM`.
//! Todo lo que no pide `PROT_EXEC` se deja continuar. Los mapeos anónimos
//! con `PROT_EXEC` (JIT) se niegan siempre.
//!
//! Esto SÍ frena a un proceso que intente mapear código no firmado, cosa que
//! el cargador de `loader.rs` por sí solo no puede (otro proceso lo evita).
//! El filtro se instala con `NO_NEW_PRIVS` y no necesita privilegios; un
//! proceso que nunca instale el filtro no está sujeto a esto (ver LIMITES.md).
//!
//! ## TOCTOU / límites de `USER_NOTIF_FLAG_CONTINUE`
//! La documentación del kernel advierte que `CONTINUE` **no** es un límite de
//! seguridad para chequeos basados en rutas: entre el veredicto y la ejecución
//! del syscall el mundo puede cambiar. Mitigamos leyendo el contenido por el
//! **mismo fd** (`open(/proc/<pid>/fd/<n>)`), no por la ruta de `readlink`.
//! Queda riesgo residual si el inode se modifica concurrentemente, o en
//! `mprotect` (ahí solo tenemos la ruta de `/proc/<pid>/maps`). Ver LIMITES.md.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use libc::{c_void, sock_filter, sock_fprog};

use crate::verify::{verify_elf, ProofVerifier};

// --- syscalls x86-64 que vigilamos ---
pub const SYS_MMAP: u32 = 9;
pub const SYS_MPROTECT: u32 = 10;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

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

/// Programa cBPF: notifica `mmap`/`mprotect`, deja pasar todo lo demás.
/// El supervisor decide según `prot`, así el filtro es simple y robusto.
fn filter_program() -> [sock_filter; 8] {
    let st = |code: u16, k: u32| sock_filter { code, jt: 0, jf: 0, k };
    let jmp = |code: u16, k: u32, jt: u8, jf: u8| sock_filter { code, jt, jf, k };
    const LD_W_ABS: u16 = 0x20;
    const JMP_JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const OFF_ARCH: u32 = 4;
    const OFF_NR: u32 = 0;
    [
        st(LD_W_ABS, OFF_ARCH),
        jmp(JMP_JEQ_K, AUDIT_ARCH_X86_64, 0, 5),
        st(LD_W_ABS, OFF_NR),
        jmp(JMP_JEQ_K, SYS_MMAP, 2, 0),
        jmp(JMP_JEQ_K, SYS_MPROTECT, 1, 0),
        st(RET_K, SECCOMP_RET_ALLOW),
        st(RET_K, SECCOMP_RET_USER_NOTIF),
        st(RET_K, SECCOMP_RET_ALLOW),
    ]
}

/// Instala el filtro en el proceso actual y devuelve el fd del listener.
/// Libre de asignaciones del heap después de construir el programa.
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

/// `prot`, `flags` y el fd de respaldo extraídos de la notificación.
#[derive(Debug, Clone, Copy)]
pub struct ExecRequest {
    pub pid: u32,
    pub nr: i32,
    pub prot: u64,
    pub flags: u64,
    pub fd: i32,
    pub addr: u64,
    pub len: u64,
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
    // mmap(addr,len,prot,flags,fd,off); mprotect(addr,len,prot)
    let (prot, flags, fd, len) = if data.nr == SYS_MMAP as i32 {
        (data.args[2], data.args[3], data.args[4] as i32, data.args[1])
    } else {
        (data.args[2], 0, -1, data.args[1])
    };
    ExecRequest { pid, nr: data.nr, prot, flags, fd, addr: data.args[0], len }
}

/// Veredicto del supervisor para una notificación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Dejar correr el syscall real (CONTINUE).
    Continue,
    /// Devolver este errno sin ejecutar el syscall.
    Deny(i32),
}

/// Ruta del `readlink` de `/proc/<pid>/fd/<fd>` (solo diagnóstico; la política
/// de verificación NO debe basarse en ella — ver TOCTOU arriba).
pub fn backing_path(pid: u32, fd: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
}

/// Lee **todos** los bytes del archivo abierto en el fd `fd` del proceso `pid`,
/// abriendo `/proc/<pid>/fd/<fd>` (duplica el open file description).
pub fn read_via_proc_fd(pid: u32, fd: i32) -> io::Result<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/fd/{fd}"))
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

/// Busca en `/proc/<pid>/maps` la VMA que contiene `addr`.
pub fn find_vma(pid: u32, addr: u64) -> io::Result<Option<MapEntry>> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    for line in text.lines() {
        // "08048000-08049000 r-xp 00000000 08:01 173521 /usr/bin/foo"
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
        let path = parts.next().and_then(|p| {
            if p.starts_with('[') {
                None
            } else {
                Some(PathBuf::from(p))
            }
        });
        return Ok(Some(MapEntry { start, end, perms, offset, path }));
    }
    Ok(None)
}

/// Política: permite `PROT_EXEC` solo si el archivo de respaldo verifica con
/// los [`ProofVerifier`] dados. Niega JIT anónimo y `mprotect` sin archivo.
pub fn policy_verify_fnbr(req: &ExecRequest, verifiers: &[&dyn ProofVerifier]) -> Verdict {
    if !req.wants_exec() {
        return Verdict::Continue;
    }
    let bytes = if req.nr == SYS_MMAP as i32 {
        if req.is_anonymous_mmap() {
            return Verdict::Deny(libc::EPERM);
        }
        if !req.is_file_backed_mmap() {
            return Verdict::Deny(libc::EPERM);
        }
        match read_via_proc_fd(req.pid, req.fd) {
            Ok(b) => b,
            Err(_) => return Verdict::Deny(libc::EPERM),
        }
    } else if req.nr == SYS_MPROTECT as i32 {
        // mprotect: solo tenemos la VMA. Riesgo TOCTOU path-based (documentado).
        let vma = match find_vma(req.pid, req.addr) {
            Ok(Some(v)) => v,
            _ => return Verdict::Deny(libc::EPERM),
        };
        let Some(path) = vma.path else {
            return Verdict::Deny(libc::EPERM);
        };
        match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return Verdict::Deny(libc::EPERM),
        }
    } else {
        return Verdict::Deny(libc::EPERM);
    };

    match verify_elf(bytes, verifiers) {
        Ok(_) => Verdict::Continue,
        Err(_) => Verdict::Deny(libc::EPERM),
    }
}

/// Atiende notificaciones hasta que `keep_going()` sea falso y no haya más
/// pendientes. `policy` decide cada pedido de `PROT_EXEC`.
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
        let verdict = if er.wants_exec() {
            policy(&er)
        } else {
            Verdict::Continue
        };

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
        handled += 1;
    }
}

/// Lanza `program`+`args` bajo el filtro seccomp y aplica `policy` a cada
/// pedido de `PROT_EXEC`. Sin privilegios (`NO_NEW_PRIVS`).
///
/// El hijo instala el filtro, manda el listener por un socketpair, hace
/// `execve` del programa y queda sujeto al filtro (persiste tras el exec).
pub fn run_supervised(
    program: &Path,
    args: &[impl AsRef<OsStr>],
    mut policy: impl FnMut(&ExecRequest) -> Verdict,
) -> io::Result<(ExitStatus, u64)> {
    let mut sv = [0i32; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (parent_sock, child_sock) = unsafe {
        (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1]))
    };

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

        let prog = CString::new(program.as_os_str().as_bytes()).unwrap_or_else(|_| unsafe { libc::_exit(92) });
        let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
        c_args.push(prog.clone());
        for a in args {
            match CString::new(a.as_ref().as_bytes()) {
                Ok(c) => c_args.push(c),
                Err(_) => unsafe { libc::_exit(92) },
            }
        }
        let mut ptrs: Vec<*const libc::c_char> = c_args.iter().map(|c| c.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        unsafe {
            libc::execv(prog.as_ptr(), ptrs.as_ptr());
            libc::_exit(93);
        }
    }

    // --- padre ---
    drop(child_sock);
    let listener = recv_fd(parent_sock.as_raw_fd())?;
    // Evita que un drop temprano cierre el sock mientras supervisamos.
    let _keep = parent_sock;

    let child_pid = pid;
    // `keep_going` puede cosechar al hijo con WNOHANG; guardamos el status
    // para no llamar waitpid dos veces (ECHILD).
    let reaped = std::sync::Mutex::new(None::<i32>);
    let handled = supervise(
        &listener,
        &mut policy,
        || {
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
            // r==0 → vivo; r<0 → error transitorio, seguimos un poco más
            true
        },
    )?;

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

/// Variante que no retiene el sock del padre más de lo necesario; expone el
/// listener crudo para tests que quieran controlar el bucle a mano.
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
        assert_eq!(p.len(), 8);
        assert_eq!(p[6].k, SECCOMP_RET_USER_NOTIF);
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
                u64::MAX, // fd=-1
                0,
            ],
        };
        let er = parse(&data, 1);
        assert!(er.wants_exec());
        assert!(er.is_anonymous_mmap());
    }
}
