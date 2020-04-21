//! Intel virtual-machine extensions (VMX)
//!
//! According to the Intel® 64 and IA-32 Architectures Software Developer’s Manual,
//! Volume 3, Section 30.2, these instructions failed if the CF or ZF bit set in
//! RFLAGS, and the error number is written to the VM-instruction error field of
//! VMCS. Therefore all function return values should be `Option` type.

use crate::PhysAddr;

/// Enter VMX root operation.
///
/// ## Safety
///
/// This function is unsafe because the caller must ensure that the given
/// `addr` points to a valid VMXON region.
#[inline]
pub unsafe fn vmxon(addr: PhysAddr) -> Option<()> {
    let err: bool;

    #[cfg(feature = "inline_asm")]
    asm!("vmxon $1; setna $0" : "=r" (err) : "m" (addr.as_u64()) : "cc", "memory" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        err = crate::asm::x86_64_asm_vmxon(addr.as_u64());
    }

    if err {
        None
    } else {
        Some(())
    }
}

/// Leaves VMX operation.
///
/// ## Safety
///
/// This function is unsafe because it must execute inside VMX operation.
#[inline]
pub unsafe fn vmxoff() -> Option<()> {
    let err: bool;

    #[cfg(feature = "inline_asm")]
    asm!("vmxoff; setna $0" : "=r" (err) :: "cc" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        err = crate::asm::x86_64_asm_vmxoff();
    }

    if err {
        None
    } else {
        Some(())
    }
}

/// Reads a specified VMCS field.
///
/// ## Safety
///
/// This function is unsafe because the caller must ensure that the given
/// VMCS `field` is supported and the relevant VMCS pointer is valid.
#[inline]
pub unsafe fn vmread(field: u64) -> Option<u64> {
    let err: bool;
    let value: u64;

    #[cfg(feature = "inline_asm")]
    asm!("vmread $2, $1; setna $0" : "=r" (err), "=r" (value) : "r" (field) : "cc" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        let mut val = 0;
        err = crate::asm::x86_64_asm_vmread(field, &mut val);
        value = val;
    }

    if err {
        None
    } else {
        Some(value)
    }
}

/// Writes a specified VMCS field.
///
/// ## Safety
///
/// This function is unsafe because the caller must ensure that the given
/// VMCS `field` is supported and the relevant VMCS pointer is valid.
#[inline]
pub unsafe fn vmwrite(field: u64, value: u64) -> Option<()> {
    let err: bool;

    #[cfg(feature = "inline_asm")]
    asm!("vmwrite $1, $2; setna $0" : "=r" (err) : "r" (value), "r" (field) : "cc" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        err = crate::asm::x86_64_asm_vmwrite(field, value);
    }

    if err {
        None
    } else {
        Some(())
    }
}

/// Loads the current VMCS pointer from memory.
///
/// ## Safety
///
/// This function is unsafe because it's possible to violate memory
/// safety through it.
#[inline]
pub unsafe fn vmptrld(addr: PhysAddr) -> Option<()> {
    let err: bool;

    #[cfg(feature = "inline_asm")]
    asm!("vmptrld $1; setna $0" : "=r" (err) : "m" (addr.as_u64()) : "cc", "memory" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        err = crate::asm::x86_64_asm_vmptrld(addr.as_u64());
    }

    if err {
        None
    } else {
        Some(())
    }
}

/// Copy VMCS data to VMCS region in memory.
///
/// ## Safety
///
/// This function is unsafe because it's possible to violate memory
/// safety through it.
#[inline]
pub unsafe fn vmclear(addr: PhysAddr) -> Option<()> {
    let err: bool;

    #[cfg(feature = "inline_asm")]
    asm!("vmclear $1; setna $0" : "=r" (err) : "m" (addr.as_u64()) : "cc", "memory" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        err = crate::asm::x86_64_asm_vmclear(addr.as_u64());
    }

    if err {
        None
    } else {
        Some(())
    }
}
