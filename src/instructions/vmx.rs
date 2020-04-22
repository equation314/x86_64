//! Intel virtual-machine extensions (VMX).
//!
//! VMX is intended to support virtualization of processor hardware and a system
//! software layer acting as a host to multiple guest software environments.
//!
//! All these function return values are [`Option`] types. From the IA-32 Intel
//! Architecture Software Developer’s Manual, Volume 3, Section 31.4: Software
//! is required to check RFLAGS.CF and RFLAGS.ZF to determine the success or
//! failure of VMX instruction executions. If the working-VMCS pointer is valid,
//! RFLAGS.ZF is set to 1 and the proper error-code is saved in the VM-instruction
//! error field of the working-VMCS.

use crate::{PhysAddr, VirtAddr};

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
        err = crate::asm::x86_64_asm_vmxon(&addr.as_u64());
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
        err = crate::asm::x86_64_asm_vmptrld(&addr.as_u64());
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
        err = crate::asm::x86_64_asm_vmclear(&addr.as_u64());
    }

    if err {
        None
    } else {
        Some(())
    }
}

/// The INVEPT type.
#[derive(Debug)]
#[repr(u64)]
pub enum InvEptType {
    /// The logical processor invalidates all mappings associated with bits
    /// 51:12 of the EPT pointer (EPTP) specified in the INVEPT descriptor.
    /// It may invalidate other mappings as well.
    SingleContext = 1,

    /// The logical processor invalidates mappings associated with all EPTPs.
    Global = 2,
}

/// The INVEPT descriptor. It comprises 128 bits and contains a 64-bit EPTP
/// value in bits 63:0.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct InvEptDescriptor {
    /// EPT pointer (EPTP)
    eptp: u64,
    reserved: u64,
}

/// Invalidates EPT-derived entries in the TLBs and paging-structure caches.
///
/// ## Safety
///
/// This function is unsafe because the caller must ensure that the given
/// EPT pointer `eptp` is valid, and it's possible to violate memory safety
/// through execution.
#[inline]
pub unsafe fn invept(invalidation: InvEptType, eptp: u64) -> Option<()> {
    let err: bool;
    let descriptor = InvEptDescriptor { eptp, reserved: 0 };

    #[cfg(feature = "inline_asm")]
    asm!("invept ($1), $2; setna $0" : "=r" (err) : "r" (&descriptor), "r" (invalidation) : "cc", "memory" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        err = crate::asm::x86_64_asm_invept(invalidation as u64, &descriptor);
    }

    if err {
        None
    } else {
        Some(())
    }
}

/// The INVVPID type.
#[derive(Debug)]
#[repr(u64)]
pub enum InvVpidType {
    /// Individual-address invalidation: the logical processor invalidates
    /// mappings for the linear address and VPID specified in the INVVPID
    /// descriptor. In some cases, it may invalidate mappings for other linear
    /// addresses (or other VPIDs) as well.
    IndividualAddress = 0,

    /// Single-context invalidation: the logical processor invalidates all
    /// mappings tagged with the VPID specified in the INVVPID descriptor. In
    /// some cases, it may invalidate mappings for other VPIDs as well.
    SingleContext = 1,

    /// All-contexts invalidation: the logical processor invalidates all mappings
    /// tagged with all VPIDs except VPID 0000H. In some cases, it may invalidate
    /// translations with VPID 0000H as well.
    AllContext = 2,

    /// Single-context invalidation, retaining global translations: the logical
    /// processor invalidates all mappings tagged with the VPID specified in the
    /// INVVPID descriptor except global translations. In some cases, it may
    /// invalidate global translations (and mappings with other VPIDs) as well.
    /// See the “Caching Translation Information” section in Chapter 4 of the
    /// IA-32 Intel Architecture Software Developer’s Manual, Volumes 3A for
    /// information about global translations.
    SingleContextNonGlobal = 3,
}

/// The INVVPID descriptor. It comprises 128 bits and consists of a VPID and a
/// linear address.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct InvVpidDescriptor {
    /// Virtual-processor identifier (VPID)
    vpid: u16,
    reserved_0: u16,
    reserved_1: u32,

    /// Guest linear address
    addr: VirtAddr,
}

/// Invalidates entries in the TLBs and paging-structure caches based on VPID.
///
/// ## Safety
///
/// This function is unsafe because it's possible to violate memory safety
/// through it.
#[inline]
pub unsafe fn invvpid(invalidation: InvVpidType, vpid: u16, addr: VirtAddr) -> Option<()> {
    let err: bool;
    let descriptor = InvVpidDescriptor {
        vpid,
        addr,
        reserved_0: 0,
        reserved_1: 0,
    };

    #[cfg(feature = "inline_asm")]
    asm!("invvpid ($1), $2; setna $0" : "=r" (err) : "r" (&descriptor), "r" (invalidation) : "cc", "memory" : "volatile");

    #[cfg(not(feature = "inline_asm"))]
    {
        err = crate::asm::x86_64_asm_invvpid(invalidation as u64, &descriptor);
    }

    if err {
        None
    } else {
        Some(())
    }
}
