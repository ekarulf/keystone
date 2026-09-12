//! Minimal read-only SSH agent: RFC 5656 keys/signatures and agent list/sign.
//! SSH keys live in a separate store so an agent never exposes an AWS identity.
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use keystone_core::{
    config::{check_not_group_or_world_writable, Paths},
    error::{KeystoneError, Result},
    identity::KeyId,
    signer::KeystoneSigningIdentity,
    store::{create_dir_all_private, write_atomic, Store},
};
use keystone_macos::{AccessPolicy, SecureEnclaveIdentity};

use crate::{
    cli::SshCommand,
    context::{print_line, Context},
};

const ALGORITHM: &[u8] = b"ecdsa-sha2-nistp256";
#[cfg(unix)]
const MAX_PACKET: usize = 256 * 1024;

fn invalid(message: impl Into<String>) -> KeystoneError {
    KeystoneError::InvalidConfiguration(message.into())
}

fn directory(context: &Context, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
    {
        return Err(invalid(
            "SSH identity names must be 1–64 ASCII letters, digits, hyphens, or underscores",
        ));
    }
    let root = std::path::absolute(&context.store.paths().data_dir)
        .map_err(|e| KeystoneError::io("cannot resolve Keystone directory", e))?;
    let dir = root.join("ssh").join(name);
    for path in [&root, &root.join("ssh"), &dir] {
        match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if !meta.is_dir() || meta.file_type().is_symlink() {
                    return Err(invalid("SSH data directories must be real directories"));
                }
                check_not_group_or_world_writable(path)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(KeystoneError::io("cannot inspect SSH data directory", e)),
        }
    }
    Ok(dir)
}

fn load(dir: &Path) -> Result<SecureEnclaveIdentity> {
    let pointer = dir.join("key-id");
    check_not_group_or_world_writable(&pointer)?;
    let id = std::fs::read_to_string(&pointer).map_err(|e| {
        KeystoneError::io("SSH identity missing; run `keystone ssh init <name>`", e)
    })?;
    let store = Store::new(Paths::rooted_at(dir));
    SecureEnclaveIdentity::restore(
        &store.load_identity(&KeyId::parse(id.trim())?)?,
        AccessPolicy::default(),
    )
}

fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn public_blob(key: &impl KeystoneSigningIdentity) -> Result<Vec<u8>> {
    let mut blob = Vec::new();
    string(&mut blob, ALGORITHM);
    string(&mut blob, b"nistp256");
    string(&mut blob, &key.public_key_sec1()?);
    Ok(blob)
}

fn public_line(key: &impl KeystoneSigningIdentity, name: &str) -> Result<String> {
    Ok(format!(
        "ecdsa-sha2-nistp256 {} {name}@keystone",
        STANDARD.encode(public_blob(key)?)
    ))
}

fn config(dir: &Path) -> Result<String> {
    // OpenSSH expands percent tokens even inside quotes. Refuse ambiguous paths.
    let quote = |path: PathBuf| -> Result<String> {
        let text = path
            .to_str()
            .ok_or_else(|| invalid("SSH paths must be UTF-8"))?;
        if text.chars().any(|c| c.is_control() || "\"\\%$".contains(c)) {
            return Err(invalid(
                "SSH paths cannot contain control characters, quotes, backslashes, %, or $",
            ));
        }
        Ok(format!("\"{text}\""))
    };
    Ok(format!(
        "Host *\n    IdentityAgent {}\n    IdentityFile {}\n    IdentitiesOnly yes\n",
        quote(dir.join("agent.sock"))?,
        quote(dir.join("identity.pub"))?
    ))
}

pub fn run(context: &Context, command: &SshCommand) -> Result<()> {
    let (SshCommand::Init(args)
    | SshCommand::PublicKey(args)
    | SshCommand::Config(args)
    | SshCommand::Agent(args)) = command;
    let dir = directory(context, &args.name)?;
    match command {
        SshCommand::Init(_) => {
            keystone_macos::require_available()?;
            let snippet = config(&dir)?;
            create_dir_all_private(&dir)?;
            let _lock = lock(&dir, "init.lock")?;
            let key = if dir
                .join("key-id")
                .try_exists()
                .map_err(|e| KeystoneError::io("cannot inspect SSH identity", e))?
            {
                load(&dir)?
            } else {
                let generated = SecureEnclaveIdentity::generate(
                    KeyId::generate(),
                    AccessPolicy::default(),
                    context.now(),
                )?;
                Store::new(Paths::rooted_at(&dir)).save_identity(&generated.metadata)?;
                write_atomic(
                    &dir.join("key-id"),
                    generated.metadata.key_id.as_str().as_bytes(),
                )?;
                generated.identity
            };
            let line = public_line(&key, &args.name)?;
            write_atomic(&dir.join("identity.pub"), format!("{line}\n").as_bytes())?;
            write_atomic(&dir.join("ssh_config"), snippet.as_bytes())?;
            context.note(format!(
                "Public key: {}\nSSH config: {}\nStart the socket with: keystone ssh agent {}\nUse the same --home or KEYSTONE_HOME setting when starting the agent.",
                dir.join("identity.pub").display(),
                dir.join("ssh_config").display(),
                args.name
            ));
            print_line(&line)
        }
        SshCommand::PublicKey(_) => print_line(&public_line(&load(&dir)?, &args.name)?),
        SshCommand::Config(_) => {
            load(&dir)?;
            print_line(&config(&dir)?)
        }
        SshCommand::Agent(_) => serve(&dir, &args.name),
    }
}

fn lock(dir: &Path, name: &str) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(dir.join(name))
        .map_err(|e| KeystoneError::io("cannot open SSH lock", e))?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|e| {
        KeystoneError::io("another Keystone process holds the SSH identity lock", e)
    })?;
    Ok(file)
}

#[cfg(any(unix, test))]
struct Reader<'a>(&'a [u8]);
#[cfg(any(unix, test))]
impl<'a> Reader<'a> {
    fn uint(&mut self) -> Option<u32> {
        let bytes = self.0.get(..4)?.try_into().ok()?;
        self.0 = &self.0[4..];
        Some(u32::from_be_bytes(bytes))
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.uint()? as usize;
        let bytes = self.0.get(..len)?;
        self.0 = &self.0[len..];
        Some(bytes)
    }
}

#[cfg(any(unix, test))]
fn mpint(out: &mut Vec<u8>, bytes: &[u8]) {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let bytes = &bytes[first..];
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        let mut positive = vec![0];
        positive.extend_from_slice(bytes);
        string(out, &positive);
    } else {
        string(out, bytes);
    }
}

#[cfg(any(unix, test))]
fn response(key: &impl KeystoneSigningIdentity, name: &str, packet: &[u8]) -> Result<Vec<u8>> {
    let blob = public_blob(key)?;
    if packet == [11] {
        let mut out = vec![12];
        out.extend_from_slice(&1u32.to_be_bytes());
        string(&mut out, &blob);
        string(&mut out, format!("{name}@keystone").as_bytes());
        return Ok(out);
    }
    if packet.first() != Some(&13) {
        return Ok(vec![5]);
    }
    let mut input = Reader(&packet[1..]);
    let parsed = (|| Some((input.string()?, input.string()?, input.uint()?)))();
    let Some((requested, message, flags)) = parsed else {
        return Ok(vec![5]);
    };
    if requested != blob || flags != 0 || !input.0.is_empty() {
        return Ok(vec![5]);
    }
    let der = key.sign_message_ecdsa_sha256(message)?;
    let signature = p256::ecdsa::Signature::from_der(der.as_bytes())
        .map_err(|_| invalid("hardware returned an invalid ECDSA signature"))?;
    let bytes = signature.to_bytes();
    let mut scalars = Vec::new();
    mpint(&mut scalars, &bytes[..32]);
    mpint(&mut scalars, &bytes[32..]);
    let mut signature_blob = Vec::new();
    string(&mut signature_blob, ALGORITHM);
    string(&mut signature_blob, &scalars);
    let mut out = vec![14];
    string(&mut out, &signature_blob);
    Ok(out)
}

#[cfg(unix)]
fn connection(
    mut stream: std::os::unix::net::UnixStream,
    key: &impl KeystoneSigningIdentity,
    name: &str,
) -> std::io::Result<()> {
    use std::io::{Read, Write};
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    loop {
        let mut header = [0; 4];
        stream.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header) as usize;
        if len == 0 || len > MAX_PACKET {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut packet = vec![0; len];
        stream.read_exact(&mut packet)?;
        let reply = response(key, name, &packet).unwrap_or_else(|_| vec![5]);
        stream.write_all(&(reply.len() as u32).to_be_bytes())?;
        stream.write_all(&reply)?;
    }
}

#[cfg(unix)]
fn serve(dir: &Path, name: &str) -> Result<()> {
    use std::{
        os::unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::UnixListener,
        },
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    load(dir)?.self_test()?;
    create_dir_all_private(dir)?;
    let _lock = lock(dir, "agent.lock")?;
    let socket = dir.join("agent.sock");
    match std::fs::symlink_metadata(&socket) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(&socket)
            .map_err(|e| KeystoneError::io("cannot remove stale SSH socket", e))?,
        Ok(_) => {
            return Err(invalid(
                "SSH socket path already exists and is not a socket",
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(KeystoneError::io("cannot inspect SSH socket", e)),
    }
    let listener = UnixListener::bind(&socket)
        .map_err(|e| KeystoneError::io("cannot bind SSH socket (try a shorter --home path)", e))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| KeystoneError::io("cannot protect SSH socket", e))?;
    eprintln!("SSH agent listening on {}", socket.display());
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = stream.map_err(|e| KeystoneError::io("cannot accept SSH connection", e))?;
        if active.load(Ordering::Relaxed) >= 16 {
            continue;
        }
        active.fetch_add(1, Ordering::Relaxed);
        let active = active.clone();
        let dir = dir.to_owned();
        let name = name.to_owned();
        std::thread::spawn(move || {
            // CryptoKit handles stay on the thread that creates them.
            if let Ok(key) = load(&dir) {
                let _ = connection(stream, &key, &name);
            }
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn serve(_: &Path, _: &str) -> Result<()> {
    Err(KeystoneError::SecureEnclaveUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::signer::DerEcdsaSignature;
    use p256::ecdsa::{
        signature::{Signer, Verifier},
        SigningKey,
    };

    struct TestKey {
        id: KeyId,
        key: SigningKey,
    }
    impl KeystoneSigningIdentity for TestKey {
        fn key_id(&self) -> &KeyId {
            &self.id
        }
        fn public_key_sec1(&self) -> Result<[u8; 65]> {
            Ok(self
                .key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap())
        }
        fn sign_message_ecdsa_sha256(&self, message: &[u8]) -> Result<DerEcdsaSignature> {
            let signature: p256::ecdsa::Signature = self.key.sign(message);
            Ok(DerEcdsaSignature::from_der(signature.to_der().as_bytes()))
        }
    }
    fn key() -> TestKey {
        TestKey {
            id: KeyId::generate(),
            key: SigningKey::from_bytes((&[1; 32]).into()).unwrap(),
        }
    }
    #[test]
    fn list_and_sign_use_ssh_encoding_and_single_sha256() {
        let key = key();
        let listing = response(&key, "test", &[11]).unwrap();
        assert_eq!(listing[0], 12);
        let mut reader = Reader(&listing[1..]);
        assert_eq!(reader.uint(), Some(1));
        let blob = reader.string().unwrap();
        assert_eq!(reader.string(), Some(b"test@keystone".as_slice()));
        assert!(reader.0.is_empty());
        let mut request = vec![13];
        string(&mut request, blob);
        string(&mut request, b"SSH authentication payload");
        request.extend_from_slice(&0u32.to_be_bytes());
        let signed = response(&key, "test", &request).unwrap();
        assert_eq!(signed[0], 14);
        let mut outer = Reader(&signed[1..]);
        let mut signature = Reader(outer.string().unwrap());
        assert_eq!(signature.string(), Some(ALGORITHM));
        let mut scalars = Reader(signature.string().unwrap());
        let mut raw = [0; 64];
        for chunk in raw.chunks_mut(32) {
            let scalar = scalars.string().unwrap();
            let scalar = scalar.strip_prefix(&[0]).unwrap_or(scalar);
            chunk[32 - scalar.len()..].copy_from_slice(scalar);
        }
        key.key
            .verifying_key()
            .verify(
                b"SSH authentication payload",
                &p256::ecdsa::Signature::from_slice(&raw).unwrap(),
            )
            .unwrap();
        assert!(outer.0.is_empty() && signature.0.is_empty() && scalars.0.is_empty());
        // Unsupported flags, trailing bytes, and another key must fail closed.
        *request.last_mut().unwrap() = 1;
        assert_eq!(response(&key, "test", &request).unwrap(), [5]);
        *request.last_mut().unwrap() = 0;
        request.push(0);
        assert_eq!(response(&key, "test", &request).unwrap(), [5]);
        request.pop();
        request[10] ^= 1;
        assert_eq!(response(&key, "test", &request).unwrap(), [5]);
    }
    #[test]
    fn malformed_and_mutating_requests_are_refused() {
        let key = key();
        for request in [
            vec![],
            vec![13],
            vec![13, 255, 255, 255, 255],
            vec![11, 0],
            vec![17],
            vec![18],
            vec![19],
            vec![27],
        ] {
            assert_eq!(response(&key, "test", &request).unwrap(), [5]);
        }
    }
    #[test]
    fn mpints_are_positive_and_minimal() {
        let mut bytes = Vec::new();
        mpint(&mut bytes, &[0, 0, 128]);
        mpint(&mut bytes, &[0, 1]);
        mpint(&mut bytes, &[0, 0]);
        let mut reader = Reader(&bytes);
        assert_eq!(reader.string(), Some([0, 128].as_slice()));
        assert_eq!(reader.string(), Some([1].as_slice()));
        assert_eq!(reader.string(), Some([].as_slice()));
    }
}
