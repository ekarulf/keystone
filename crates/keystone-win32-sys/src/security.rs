//! Owner and DACL inspection, and creating owner-only files.
//!
//! Windows has no `chmod`, so `keystone-core`'s uid-and-mode check has no direct
//! translation. What it is *for* does translate: refuse to read a file another
//! local user could have written, and never create one they could read. Here that
//! becomes two operations.
//!
//! [`file_access`] answers "who can write this, and who owns it" by reading the
//! file's owner SID and walking its DACL. [`owner_only_dacl`] builds the DACL that
//! grants the calling user alone, which [`create_owner_only_file`] installs at
//! creation and [`apply_owner_only_dacl`] applies to a path that already exists —
//! both with inheritance blocked, since a file inside an inheriting directory would
//! otherwise silently acquire that directory's ACEs.
//!
//! The DACL is deliberately built by hand rather than copied from the parent.
//! Inheriting is how a private file quietly becomes group-readable when someone
//! loosens a profile directory.

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_SUCCESS, GENERIC_WRITE,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAce, CreateWellKnownSid, EqualSid, GetAce,
    GetAclInformation, GetLengthSid, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TokenUser, WinBuiltinAdministratorsSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL, ACL_REVISION,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE, MAXIMUM_ALLOWED,
    SECURITY_DESCRIPTOR_REVISION, SYSTEM_ACCESS_FILTER_ACE_TYPE, SYSTEM_ALARM_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::{wide, Result, Win32Error};

/// The access bits that let a holder change a file's contents or its ACL.
///
/// `WRITE_DAC` and `WRITE_OWNER` matter as much as `FILE_WRITE_DATA`: a principal
/// who can rewrite the ACL can grant itself write access, so treating it as
/// harmless would make the whole check decorative. `DELETE` counts too — replacing
/// a file wholesale is as good as editing it.
/// `MAXIMUM_ALLOWED` counts as well, and is the easiest one to miss: it is not a
/// specific right but a request for every right the DACL permits, resolved when the
/// file is opened. An ACE granting it to another principal grants that principal
/// whatever else the DACL would allow, so omitting it from this mask would let a
/// single bit defeat every other entry here.
const DANGEROUS_WRITE_MASK: u32 = {
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_APPEND_DATA: u32 = 0x0004;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_WRITE_EA: u32 = 0x0010;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL
        | MAXIMUM_ALLOWED
};

/// Full control over a file, for the owner-only ACE.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// How an ACE's SID is reached, which depends on its type.
///
/// Windows defines *five* allow-ACE types, not one, and they do not share a
/// layout. `ACCESS_ALLOWED_ACE` puts the SID immediately after the mask; the object
/// and callback-object forms insert a flags field and up to two GUIDs before it, and
/// the compound form inserts two more fields and a second SID. Reading every type as
/// `ACCESS_ALLOWED_ACE` would take the first bytes of a GUID as the start of a SID,
/// so the type is classified before the SID is touched.
enum AceKind {
    /// The SID follows the mask directly: `ACCESS_ALLOWED_ACE_TYPE` and
    /// `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`, which appends opaque condition bytes
    /// *after* the SID and so does not move it.
    SidAfterMask,
    /// `ACCESS_ALLOWED_OBJECT_ACE_TYPE` and
    /// `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE`: a `Flags` u32, then up to two
    /// GUIDs, each present only if its bit is set in `Flags`.
    ObjectAce,
    /// An allow-ACE whose grantee this code declines to determine, currently only
    /// `ACCESS_ALLOWED_COMPOUND_ACE_TYPE`. It carries two SIDs — a server and a
    /// client — and their order is not pinned down by any header or documentation
    /// available here, so picking one would be a guess in a place where guessing
    /// wrong means reading a private file that another principal can write. It is
    /// counted as a foreign writer instead. Nothing is lost: compound ACEs are a
    /// legacy impersonation mechanism that does not appear on files, and an entry
    /// whose grant depends on a *second* identity is not "the owner alone" in any
    /// reading of it.
    OpaqueAllow,
    /// A deny, audit, or alarm ACE. Recognized, and cannot grant access to anyone:
    /// a deny-ACE cannot make another principal a writer, and audit and alarm ACEs
    /// only ask for logging. Skipping these is sound rather than merely convenient.
    CannotGrant,
    /// A type this code has never heard of. Counted as a foreign writer rather than
    /// skipped: an unknown type may well grant access, its SID cannot be located to
    /// see to whom, and "assume harmless" is the unsafe assumption.
    Unknown,
}

impl AceKind {
    fn classify(ace_type: u8) -> Self {
        match u32::from(ace_type) {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => Self::SidAfterMask,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                Self::ObjectAce
            }
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE => Self::OpaqueAllow,
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_MANDATORY_LABEL_ACE_TYPE
            | SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
            | SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
            | SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
            | SYSTEM_ACCESS_FILTER_ACE_TYPE => Self::CannotGrant,
            _ => Self::Unknown,
        }
    }
}

/// Where an allow-ACE's SID starts, as a byte offset from the ACE.
///
/// `None` means the ACE is shorter than the fields its own type requires, so the
/// offset would point past it. That is a malformed ACL rather than a hostile one,
/// but the caller treats it the same way — the SID cannot be read, so the grantee is
/// unknown.
///
/// Every offset returned is checked against `ace_size` before it is handed back, so
/// a caller that respects the `None` cannot be led outside the ACE by a crafted
/// header.
fn sid_offset(ace: *const core::ffi::c_void, kind: &AceKind, ace_size: usize) -> Option<usize> {
    /// `ACE_HEADER` plus the `ACCESS_MASK`, common to every ACE type.
    const AFTER_MASK: usize = std::mem::size_of::<ACE_HEADER>() + std::mem::size_of::<u32>();
    const GUID_LEN: usize = std::mem::size_of::<windows_sys::core::GUID>();

    let offset = match kind {
        AceKind::SidAfterMask => AFTER_MASK,
        AceKind::ObjectAce => {
            // The two GUIDs are optional and independent: each is present only if
            // its bit is set, and `InheritedObjectType` can be present while
            // `ObjectType` is not. Assuming both — the shape of the struct
            // definition — would skip 32 bytes past a SID that starts after 4.
            let flags_end = AFTER_MASK + std::mem::size_of::<u32>();
            if flags_end > ace_size {
                return None;
            }
            // SAFETY: `flags_end <= ace_size`, so the `Flags` field lies within the
            // ACE, which lives in the DACL buffer for the duration of the walk.
            // `read_unaligned` because nothing guarantees the ACE's alignment
            // within that buffer.
            #[allow(unsafe_code)]
            let flags = unsafe {
                ace.cast::<u8>()
                    .add(AFTER_MASK)
                    .cast::<u32>()
                    .read_unaligned()
            };
            let guids = usize::from(flags & ACE_OBJECT_TYPE_PRESENT != 0)
                + usize::from(flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0);
            flags_end + guids * GUID_LEN
        }
        // These never reach here: the caller counts them without asking for an
        // offset. Matched explicitly so adding a variant is a compile error rather
        // than a silently wrong offset.
        AceKind::OpaqueAllow | AceKind::CannotGrant | AceKind::Unknown => return None,
    };

    // A SID is at least 8 bytes (revision, sub-authority count, and the 6-byte
    // identifier authority), so an ACE that does not have that much left after the
    // fixed fields cannot hold one.
    if offset.checked_add(8)? > ace_size {
        return None;
    }
    Some(offset)
}

/// An owned copy of a SID.
///
/// Stored as bytes so the SID outlives whatever buffer it was read from. A `PSID`
/// borrowed from a token or a security descriptor dangles once that memory is
/// freed, which is easy to get wrong and impossible to detect afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// Copy the SID at `psid`.
    ///
    /// # Safety of the caller's pointer
    ///
    /// Not marked `unsafe` because it is only reachable from this module, where
    /// every call site passes a pointer that a Win32 call just wrote and that is
    /// still live. The validity check makes a garbage pointer fail rather than
    /// read arbitrary memory for a length.
    fn from_psid(psid: PSID) -> Result<Self> {
        if psid.is_null() {
            return Err(Win32Error::new("IsValidSid", ERROR_SUCCESS as i32));
        }
        // SAFETY: `psid` is non-null and points at a SID written by a Win32 call.
        // `IsValidSid` is the documented way to check it before trusting its
        // internal length fields.
        #[allow(unsafe_code)]
        let valid = unsafe { IsValidSid(psid) } != 0;
        if !valid {
            return Err(Win32Error::last("IsValidSid"));
        }
        // SAFETY: validated above, so the sub-authority count is in range and
        // `GetLengthSid` reads only within the SID.
        #[allow(unsafe_code)]
        let length = unsafe { GetLengthSid(psid) } as usize;
        if length == 0 {
            return Err(Win32Error::last("GetLengthSid"));
        }
        let mut bytes = vec![0u8; length];
        // SAFETY: `psid` is a valid SID of `length` bytes and `bytes` is exactly
        // that long, so the copy stays in bounds of both.
        #[allow(unsafe_code)]
        unsafe {
            std::ptr::copy_nonoverlapping(psid.cast::<u8>(), bytes.as_mut_ptr(), length);
        }
        Ok(Self(bytes))
    }

    fn as_psid(&self) -> PSID {
        // Cast of a shared reference to the `*mut c_void` the API wants. Every
        // Win32 function this is passed to treats the SID as read-only; none of
        // them is documented to modify it.
        self.0.as_ptr() as PSID
    }

    /// The SID's byte length, for sizing an ACL.
    fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether two SIDs name the same principal.
    pub fn matches(&self, other: &Sid) -> bool {
        // `EqualSid` rather than a byte comparison: equal SIDs are byte-identical
        // in practice, but the comparison is the API's to define.
        // SAFETY: both pointers reference validated SIDs owned by `self`/`other`.
        #[allow(unsafe_code)]
        let equal = unsafe { EqualSid(self.as_psid(), other.as_psid()) } != 0;
        equal
    }
}

/// The SID of the user this process runs as.
pub fn current_user_sid() -> Result<Sid> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no closing;
    // `token` is a valid out-pointer.
    #[allow(unsafe_code)]
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0;
    if !opened {
        return Err(Win32Error::last("OpenProcessToken"));
    }
    let token = TokenHandle(token);

    let mut needed: u32 = 0;
    // SAFETY: a null buffer with zero length asks for the required size. The call
    // is expected to fail with ERROR_INSUFFICIENT_BUFFER; `needed` is written.
    #[allow(unsafe_code)]
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(Win32Error::last("GetTokenInformation"));
    }

    // Over-aligned backing store: the buffer is reinterpreted as a `TOKEN_USER`,
    // which contains a pointer, so it must be pointer-aligned. A `Vec<u8>` is
    // only byte-aligned, and reading a misaligned pointer field is undefined.
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words.max(1)];
    // SAFETY: `buffer` is at least `needed` bytes and that length is passed, so
    // the call cannot write past it.
    #[allow(unsafe_code)]
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } != 0;
    if !ok {
        return Err(Win32Error::last("GetTokenInformation"));
    }

    // SAFETY: the call above filled `buffer` with a `TOKEN_USER` followed by the
    // SID it points into. The buffer is pointer-aligned by construction and
    // outlives this read, and the SID is copied out before it is dropped.
    #[allow(unsafe_code)]
    let psid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    Sid::from_psid(psid)
}

/// Whether `sid` is the built-in Administrators group.
///
/// The counterpart of accepting root as an owner on Unix. Administrators can take
/// ownership of any file and rewrite its ACL, so an Administrators-owned file is
/// not a weaker position than the caller owning it — and a Keystone installed
/// machine-wide produces exactly that.
///
/// A failure to construct the well-known SID is reported as "not Administrators",
/// which fails closed: the caller then rejects the file.
pub fn is_administrators(sid: &Sid) -> bool {
    administrators_sid().is_ok_and(|admins| sid.matches(&admins))
}

fn administrators_sid() -> Result<Sid> {
    // `SECURITY_MAX_SID_SIZE` is the documented upper bound for any SID, so this
    // buffer cannot be too small and no size query is needed.
    let mut buffer = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = SECURITY_MAX_SID_SIZE;
    // SAFETY: the buffer is at least `size` bytes and that length is passed, so the
    // call cannot write past it. A null domain SID is correct for a built-in group.
    #[allow(unsafe_code)]
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0;
    if !ok {
        return Err(Win32Error::last("CreateWellKnownSid"));
    }
    Sid::from_psid(buffer.as_mut_ptr().cast())
}

/// A process token handle, closed on drop.
struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from a successful `OpenProcessToken` and is
            // closed exactly once.
            #[allow(unsafe_code)]
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// What the DACL of a file permits, reduced to the two questions Keystone asks.
#[derive(Debug, Clone)]
pub struct FileAccess {
    /// The file's owner.
    pub owner: Sid,
    /// SIDs, other than `expected`, that hold write-equivalent access.
    ///
    /// Non-empty means some other principal can change the file. Reported as a
    /// count rather than resolved to names: resolving a SID can hit the network on
    /// a domain-joined machine, and `credential-process` must not block on that.
    pub other_writers: usize,
    /// Whether the DACL was absent.
    ///
    /// A NULL DACL grants everyone full control. It is reported separately because
    /// "no ACEs" and "no DACL" mean opposite things, and treating an absent DACL as
    /// an empty one would read the most permissive case as the most restrictive.
    pub dacl_absent: bool,
}

/// Read `path`'s owner and count principals other than `expected` that can write.
pub fn file_access(path: &std::path::Path, expected: &Sid) -> Result<FileAccess> {
    let wide_path = wide(&path.to_string_lossy());
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

    // SAFETY: `wide_path` is NUL-terminated and outlives the call; the four
    // out-parameters are valid pointers. On success the descriptor owns the memory
    // that `owner` and `dacl` point into, and it is freed by `Descriptor`'s drop
    // after both have been read.
    #[allow(unsafe_code)]
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(Win32Error::new("GetNamedSecurityInfoW", status as i32));
    }
    let _descriptor = Descriptor(descriptor);

    let owner = Sid::from_psid(owner)?;

    // A NULL DACL is not an empty DACL: it grants full control to everyone.
    if dacl.is_null() {
        return Ok(FileAccess {
            owner,
            other_writers: 0,
            dacl_absent: true,
        });
    }

    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is non-null and came from the call above; `info` is a valid
    // out-buffer of the size passed.
    #[allow(unsafe_code)]
    let ok = unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } != 0;
    if !ok {
        return Err(Win32Error::last("GetAclInformation"));
    }

    let mut other_writers = 0usize;
    for index in 0..info.AceCount {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `index` is below the ACE count the ACL just reported, so the ACE
        // exists; `ace` is a valid out-pointer.
        #[allow(unsafe_code)]
        let ok = unsafe { GetAce(dacl, index, &mut ace) } != 0;
        if !ok {
            return Err(Win32Error::last("GetAce"));
        }
        // SAFETY: `ace` points at an ACE inside the DACL, which outlives this
        // read. `ACE_HEADER` is the common prefix of every ACE type, so this is
        // valid before the type is known — and nothing past it is read until the
        // type has been classified.
        #[allow(unsafe_code)]
        let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
        let ace_size = usize::from(header.AceSize);
        let kind = AceKind::classify(header.AceType);
        match kind {
            // Cannot grant anything to anyone, so it cannot make another principal
            // a writer.
            AceKind::CannotGrant => continue,
            // Might grant, to someone this code cannot identify. Fail closed: the
            // caller refuses the file and tells the user to reset its ACL.
            AceKind::OpaqueAllow | AceKind::Unknown => {
                other_writers += 1;
                continue;
            }
            AceKind::SidAfterMask | AceKind::ObjectAce => {}
        }

        // Every allow-ACE carries the mask immediately after the header; only the
        // SID moves. Checked against the header's own size first, since a truncated
        // ACE would otherwise have its mask read from the next one.
        if ace_size < std::mem::size_of::<ACE_HEADER>() + std::mem::size_of::<u32>() {
            other_writers += 1;
            continue;
        }
        // SAFETY: `ace` is a live ACE at least large enough for the header and the
        // mask, and `ACCESS_ALLOWED_ACE`'s first two fields are exactly those, in
        // that order, for every allow type. Read unaligned because the ACL packs
        // ACEs without regard to this struct's alignment.
        #[allow(unsafe_code)]
        let mask = unsafe { ace.cast::<ACCESS_ALLOWED_ACE>().read_unaligned().Mask };
        if mask & DANGEROUS_WRITE_MASK == 0 {
            continue;
        }

        let Some(sid_offset) = sid_offset(ace, &kind, ace_size) else {
            // The ACE is too short to hold the fields its own type requires, so its
            // SID cannot be read. Malformed rather than hostile, but the grantee is
            // just as unknown either way.
            other_writers += 1;
            continue;
        };
        // SAFETY: `sid_offset` is within the ACE, whose size the header reports and
        // which lives inside the DACL buffer. `Sid::from_psid` validates the SID
        // before copying it.
        #[allow(unsafe_code)]
        let psid = unsafe { ace.cast::<u8>().add(sid_offset) } as PSID;
        let sid = Sid::from_psid(psid)?;
        if !sid.matches(expected) {
            other_writers += 1;
        }
    }

    Ok(FileAccess {
        owner,
        other_writers,
        dacl_absent: false,
    })
}

/// A security descriptor from `GetNamedSecurityInfoW`, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `GetNamedSecurityInfoW` allocates the descriptor with
            // `LocalAlloc`, so `LocalFree` is the matching deallocation, called
            // exactly once.
            #[allow(unsafe_code)]
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// A self-contained DACL granting full control to one SID and no one else.
///
/// The buffer is owned and pointer-aligned, so it can be handed to
/// `SetNamedSecurityInfoW` and stays valid for the call.
pub struct OwnerOnlyDacl {
    buffer: Vec<usize>,
}

impl OwnerOnlyDacl {
    fn as_acl(&self) -> *const ACL {
        self.buffer.as_ptr().cast()
    }
}

/// Build a DACL whose only entry grants `sid` full control.
pub fn owner_only_dacl(sid: &Sid) -> Result<OwnerOnlyDacl> {
    // One `ACCESS_ALLOWED_ACE` holds its SID inline starting at `SidStart`, so the
    // ACE is the struct plus the SID minus the 4 bytes `SidStart` already occupies.
    let ace_size =
        std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>() + sid.len();
    let acl_size = std::mem::size_of::<ACL>() + ace_size;

    let words = acl_size.div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words.max(1)];
    let acl = buffer.as_mut_ptr().cast::<ACL>();

    // SAFETY: `acl` points at `acl_size` or more zeroed, pointer-aligned bytes,
    // and that size is what is declared to `InitializeAcl`.
    #[allow(unsafe_code)]
    let ok = unsafe { InitializeAcl(acl, acl_size as u32, ACL_REVISION) } != 0;
    if !ok {
        return Err(Win32Error::last("InitializeAcl"));
    }

    // SAFETY: the ACL was just initialized with room for exactly this ACE, and
    // `sid` is a validated SID that outlives the call.
    #[allow(unsafe_code)]
    let ok = unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid.as_psid()) } != 0;
    if !ok {
        return Err(Win32Error::last("AddAccessAllowedAce"));
    }

    Ok(OwnerOnlyDacl { buffer })
}

/// Replace `path`'s DACL with one granting only the current user.
///
/// `PROTECTED_DACL_SECURITY_INFORMATION` blocks inheritance. Without it the file
/// keeps whatever ACEs its directory propagates, so a loosened profile directory
/// would silently widen access to a file this function reports as private.
pub fn apply_owner_only_dacl(path: &std::path::Path, sid: &Sid) -> Result<()> {
    let dacl = owner_only_dacl(sid)?;
    let wide_path = wide(&path.to_string_lossy());
    // SAFETY: `wide_path` and `dacl` both outlive the call; the SACL and the
    // owner/group pointers are null because only the DACL is being set.
    #[allow(unsafe_code)]
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl.as_acl(),
            std::ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(Win32Error::new("SetNamedSecurityInfoW", status as i32));
    }
    Ok(())
}

/// Create a new file whose DACL grants only `sid`, and return its handle.
///
/// The DACL is supplied at creation rather than applied afterwards, which is the
/// whole reason this exists instead of a `File::create` followed by
/// [`apply_owner_only_dacl`]. Between those two calls the file inherits its
/// directory's ACEs, so private contents written in that window are readable by
/// whoever the directory allows. Unix avoids the same window with `O_CREAT` plus a
/// mode; this is the Windows spelling of it.
///
/// `CREATE_NEW` fails if the path exists, matching `O_EXCL`: opening an existing
/// file would write private contents under someone else's DACL, since a
/// security descriptor passed to `CreateFileW` is ignored when the file already
/// exists.
///
/// An existing file is reported as `Ok(None)` rather than as an error, so the
/// caller can describe that case in its own words the way the Unix path does.
pub fn create_owner_only_file(path: &std::path::Path, sid: &Sid) -> Result<Option<OwnedHandle>> {
    let dacl = owner_only_dacl(sid)?;

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let psd: PSECURITY_DESCRIPTOR = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    // SAFETY: `psd` points at a zeroed, correctly aligned `SECURITY_DESCRIPTOR`
    // that outlives the `CreateFileW` call below.
    #[allow(unsafe_code)]
    let ok = unsafe { InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) } != 0;
    if !ok {
        return Err(Win32Error::last("InitializeSecurityDescriptor"));
    }

    // `bDaclPresent` true with a non-null DACL. Passing null here would mean "no
    // DACL", which grants everyone full control — the opposite of the intent.
    // SAFETY: the descriptor is initialized and `dacl` outlives both this call and
    // the `CreateFileW` that consumes the descriptor.
    #[allow(unsafe_code)]
    let ok = unsafe { SetSecurityDescriptorDacl(psd, 1, dacl.as_acl(), 0) } != 0;
    if !ok {
        return Err(Win32Error::last("SetSecurityDescriptorDacl"));
    }

    // Block inheritance, the counterpart of the `PROTECTED_DACL_SECURITY_INFORMATION`
    // that [`apply_owner_only_dacl`] passes. An explicit DACL handed to `CreateFileW`
    // does *not* by itself stop the directory's inheritable ACEs from being merged
    // into the new file's DACL, so without this the file is created with the one ACE
    // below plus whatever the parent propagates — which is precisely the widening
    // this function exists to prevent.
    // SAFETY: `psd` points at the initialized descriptor above, and the two control
    // arguments are a mask and the bits to set within it.
    #[allow(unsafe_code)]
    let ok =
        unsafe { SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED) } != 0;
    if !ok {
        return Err(Win32Error::last("SetSecurityDescriptorControl"));
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        // The handle must not pass to child processes: Keystone spawns none for
        // this file, and an inheritable handle to a private file is a leak waiting
        // for the first time it does.
        bInheritHandle: 0,
    };

    let wide_path = wide(&path.to_string_lossy());
    // SAFETY: `wide_path`, `attributes`, `descriptor`, and `dacl` all outlive the
    // call. `FILE_SHARE_NONE` and a null template handle are valid arguments.
    #[allow(unsafe_code)]
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_NONE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = Win32Error::last("CreateFileW");
        if error.code == ERROR_FILE_EXISTS as i32 || error.code == ERROR_ALREADY_EXISTS as i32 {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(OwnedHandle(handle)))
}

/// A file handle, closed on drop.
///
/// Convertible into a [`std::fs::File`] so the caller writes through the standard
/// library rather than through more FFI. The conversion is the point at which this
/// crate's job ends.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Take ownership of the handle as a `File`.
    ///
    /// `into_raw_handle`-style transfer: the `OwnedHandle` is consumed, so the
    /// handle is closed once, by the `File`.
    pub fn into_file(self) -> std::fs::File {
        use std::os::windows::io::FromRawHandle;
        let handle = self.0;
        // Do not run this type's `Drop`: ownership moves to the `File`, and
        // closing the handle twice could close an unrelated handle that reused the
        // value.
        std::mem::forget(self);
        // SAFETY: `handle` came from a successful `CreateFileW`, is not
        // `INVALID_HANDLE_VALUE`, and is not owned by anything else now that this
        // wrapper has been forgotten.
        #[allow(unsafe_code)]
        unsafe {
            std::fs::File::from_raw_handle(handle.cast())
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `CreateFileW` and, because
        // `into_file` forgets `self`, is closed exactly once.
        #[allow(unsafe_code)]
        unsafe {
            CloseHandle(self.0);
        }
    }
}
