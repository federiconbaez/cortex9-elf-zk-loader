//! Cargador mínimo de ELF64 x86-64 `ET_EXEC` estático en el proceso actual.
//!
//! Política:
//! - Solo acepta un [`VerifiedElf`]: no existe función pública que mapee con
//!   `PROT_EXEC` a partir de bytes sin verificar.
//! - W^X: rechaza segmentos escribibles y ejecutables a la vez.
//! - Mapea con `MAP_FIXED_NOREPLACE` (nunca pisa mapeos existentes), primero
//!   `RW`, copia, y recién después `mprotect` a los permisos finales.
//!
//! No es un `execve`: no hay pila nueva, ni auxv, ni libc del invitado. El
//! punto de entrada se llama como `extern "C" fn() -> i64`.

use goblin::elf::header::{EM_X86_64, ET_EXEC};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_INTERP, PT_LOAD};
use goblin::elf::Elf;

use crate::verify::{verify_elf, ProofVerifier, VerifiedElf, VerifyError};

#[derive(Debug)]
pub enum LoadError {
    /// La verificación falló: no se llegó a mapear nada.
    Refused(VerifyError),
    Parse(String),
    Unsupported(&'static str),
    WriteAndExec { vaddr: u64 },
    SharedPage { vaddr: u64 },
    Mmap { addr: u64, errno: i32 },
    Mprotect { addr: u64, errno: i32 },
    Io(std::io::Error),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for LoadError {}

const PAGE: u64 = 4096;
fn down(x: u64) -> u64 {
    x & !(PAGE - 1)
}
fn up(x: u64) -> u64 {
    (x + PAGE - 1) & !(PAGE - 1)
}

/// Imagen cargada. Se desmapea al soltarse.
#[derive(Debug)]
pub struct LoadedImage {
    start: u64,
    len: u64,
    entry: u64,
    pub segments: Vec<(u64, u64, i32)>,
}

impl LoadedImage {
    pub fn range(&self) -> (u64, u64) {
        (self.start, self.start + self.len)
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// Llama al punto de entrada del invitado.
    ///
    /// # Safety
    /// Ejecuta código nativo arbitrario (aunque firmado) dentro de este
    /// proceso. La firma prueba origen, no inocuidad.
    pub unsafe fn call_entry(&self) -> i64 {
        let f: extern "C" fn() -> i64 = std::mem::transmute(self.entry as usize);
        f()
    }
}

impl Drop for LoadedImage {
    fn drop(&mut self) {
        // SAFETY: rango mapeado por nosotros en `load`.
        unsafe { libc::munmap(self.start as *mut libc::c_void, self.len as usize) };
    }
}

fn prot_of(flags: u32) -> i32 {
    let mut p = 0;
    if flags & PF_R != 0 {
        p |= libc::PROT_READ;
    }
    if flags & PF_W != 0 {
        p |= libc::PROT_WRITE;
    }
    if flags & PF_X != 0 {
        p |= libc::PROT_EXEC;
    }
    p
}

/// Único camino a `PROT_EXEC`: requiere un `VerifiedElf`.
pub fn load(v: &VerifiedElf) -> Result<LoadedImage, LoadError> {
    let bytes = v.bytes();
    let elf = Elf::parse(bytes).map_err(|e| LoadError::Parse(e.to_string()))?;
    if !elf.is_64 || elf.header.e_machine != EM_X86_64 {
        return Err(LoadError::Unsupported("solo ELF64 x86-64"));
    }
    if elf.header.e_type != ET_EXEC {
        return Err(LoadError::Unsupported("solo ET_EXEC estático (sin PIE)"));
    }
    if elf.program_headers.iter().any(|p| p.p_type == PT_INTERP) || elf.dynamic.is_some() {
        return Err(LoadError::Unsupported("binarios dinámicos no soportados"));
    }
    let loads: Vec<_> = elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD).collect();
    if loads.is_empty() {
        return Err(LoadError::Unsupported("sin PT_LOAD"));
    }

    // Validaciones antes de mapear nada.
    let mut pages: Vec<(u64, u64)> = Vec::new();
    for p in &loads {
        if p.p_flags & PF_W != 0 && p.p_flags & PF_X != 0 {
            return Err(LoadError::WriteAndExec { vaddr: p.p_vaddr });
        }
        if p.p_filesz > p.p_memsz
            || p.p_offset.checked_add(p.p_filesz).is_none_or(|e| e > bytes.len() as u64)
        {
            return Err(LoadError::Parse("segmento fuera del archivo".into()));
        }
        let (a, b) = (down(p.p_vaddr), up(p.p_vaddr + p.p_memsz));
        if pages.iter().any(|&(x, y)| a < y && x < b) {
            // Dos segmentos con permisos distintos en la misma página: no
            // se puede respetar W^X por página. Se rechaza.
            return Err(LoadError::SharedPage { vaddr: p.p_vaddr });
        }
        pages.push((a, b));
    }
    let start = pages.iter().map(|p| p.0).min().unwrap();
    let end = pages.iter().map(|p| p.1).max().unwrap();
    let len = end - start;

    // SAFETY: mapeo anónimo nuevo; MAP_FIXED_NOREPLACE falla con EEXIST en
    // lugar de pisar memoria existente del proceso.
    let addr = unsafe {
        libc::mmap(
            start as *mut libc::c_void,
            len as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED || addr as u64 != start {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if addr != libc::MAP_FAILED {
            unsafe { libc::munmap(addr, len as usize) };
        }
        return Err(LoadError::Mmap { addr: start, errno });
    }
    let mut img = LoadedImage { start, len, entry: elf.entry, segments: Vec::new() };

    for p in &loads {
        let src = &bytes[p.p_offset as usize..(p.p_offset + p.p_filesz) as usize];
        // SAFETY: destino dentro de [start, end) recién mapeado RW.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), p.p_vaddr as *mut u8, src.len()) };
    }
    // Páginas entre segmentos quedan sin permisos.
    unsafe { libc::mprotect(start as *mut libc::c_void, len as usize, libc::PROT_NONE) };
    for p in &loads {
        let (a, b) = (down(p.p_vaddr), up(p.p_vaddr + p.p_memsz));
        let prot = prot_of(p.p_flags);
        // SAFETY: rango propio.
        if unsafe { libc::mprotect(a as *mut libc::c_void, (b - a) as usize, prot) } != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(LoadError::Mprotect { addr: a, errno });
        }
        img.segments.push((a, b, prot));
    }
    if !img.segments.iter().any(|&(a, b, p)| p & libc::PROT_EXEC != 0 && (a..b).contains(&img.entry)) {
        return Err(LoadError::Unsupported("el entry no cae en un segmento ejecutable"));
    }
    Ok(img)
}

/// Lee, verifica y carga. Si la verificación falla, devuelve
/// `LoadError::Refused` **sin** haber llamado a `mmap`.
pub fn load_path(path: &std::path::Path, verifiers: &[&dyn ProofVerifier]) -> Result<LoadedImage, LoadError> {
    let bytes = std::fs::read(path).map_err(LoadError::Io)?;
    let v = verify_elf(bytes, verifiers).map_err(LoadError::Refused)?;
    load(&v)
}
