use crate::error::{IpcError, IpcResult};
use crate::protocol::{IpcRequest, IpcResponse, LockState, SecretBytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

pub const MAGIC: [u8; 4] = *b"SIGL";
pub const PROTOCOL_VERSION: u8 = 2;
pub const HEADER_LEN: usize = 8;
pub const MAX_PAYLOAD_SIZE: usize = 4096;
pub const MAX_FRAME_SIZE: usize = MAX_PAYLOAD_SIZE + HEADER_LEN;

// Request Opcodes
pub const OP_GET_APPLICATION_SECRET: u8 = 0x01;
pub const OP_GET_LOCK_STATUS: u8 = 0x02;
pub const OP_LOCK: u8 = 0x03;
pub const OP_UNLOCK_WITH_PASSWORD: u8 = 0x04;
pub const OP_ROTATE_SLOT_PASSWORD: u8 = 0x05;
pub const OP_RECOVER_AND_SYNC: u8 = 0x06;
pub const OP_PING: u8 = 0x07;

// Response Status Codes
pub const STATUS_SUCCESS: u8 = 0x00;
pub const STATUS_SECRET: u8 = 0x01;
pub const STATUS_LOCK_STATUS: u8 = 0x02;
pub const STATUS_LOCKED: u8 = 0x03;
pub const STATUS_DESYNCED: u8 = 0x04;
pub const STATUS_CANCELLED: u8 = 0x05;
pub const STATUS_ACCESS_DENIED: u8 = 0x06;
pub const STATUS_ERROR: u8 = 0x07;

/// Encodes an `IpcRequest` into wire format bytes: `[magic (4)][version (1)][opcode (1)][len (2)][payload]`.
pub fn encode_request(req: &IpcRequest, out: &mut Vec<u8>) -> IpcResult<()> {
    out.clear();
    out.extend_from_slice(&MAGIC);
    out.push(PROTOCOL_VERSION);

    let (opcode, mut payload) = match req {
        IpcRequest::GetApplicationSecret {
            namespace,
            subject,
            purpose,
        } => {
            let mut p = Vec::with_capacity(namespace.len() + subject.len() + purpose.len() + 6);
            encode_string(&mut p, namespace)?;
            encode_string(&mut p, subject)?;
            encode_string(&mut p, purpose)?;
            (OP_GET_APPLICATION_SECRET, p)
        }
        IpcRequest::GetLockStatus => (OP_GET_LOCK_STATUS, Vec::new()),
        IpcRequest::Lock => (OP_LOCK, Vec::new()),
        IpcRequest::UnlockWithPassword { password } => {
            let mut p = Vec::with_capacity(password.len() + 2);
            encode_string(&mut p, password)?;
            (OP_UNLOCK_WITH_PASSWORD, p)
        }
        IpcRequest::RotateSlotPassword {
            old_password,
            new_password,
        } => {
            let mut p = Vec::with_capacity(old_password.len() + new_password.len() + 4);
            encode_string(&mut p, old_password)?;
            encode_string(&mut p, new_password)?;
            (OP_ROTATE_SLOT_PASSWORD, p)
        }
        IpcRequest::RecoverAndSyncWithCurrentPassword {
            recovery_secret,
            new_system_password,
        } => {
            let mut p = Vec::with_capacity(recovery_secret.len() + new_system_password.len() + 4);
            encode_string(&mut p, recovery_secret)?;
            encode_string(&mut p, new_system_password)?;
            (OP_RECOVER_AND_SYNC, p)
        }
        IpcRequest::Ping => (OP_PING, Vec::new()),
    };

    if payload.len() > MAX_PAYLOAD_SIZE {
        payload.zeroize();
        return Err(IpcError::FrameTooLarge(payload.len(), MAX_PAYLOAD_SIZE));
    }

    out.push(opcode);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    payload.zeroize();

    Ok(())
}

/// Decodes an `IpcRequest` from opcode and payload bytes.
pub fn decode_request(opcode: u8, payload: &[u8]) -> IpcResult<IpcRequest> {
    match opcode {
        OP_GET_APPLICATION_SECRET => {
            let mut offset = 0;
            let namespace = decode_string(payload, &mut offset)?;
            let subject = decode_string(payload, &mut offset)?;
            let purpose = decode_string(payload, &mut offset)?;
            Ok(IpcRequest::GetApplicationSecret {
                namespace,
                subject,
                purpose,
            })
        }
        OP_GET_LOCK_STATUS => Ok(IpcRequest::GetLockStatus),
        OP_LOCK => Ok(IpcRequest::Lock),
        OP_UNLOCK_WITH_PASSWORD => {
            let mut offset = 0;
            let password = decode_string(payload, &mut offset)?;
            Ok(IpcRequest::UnlockWithPassword { password })
        }
        OP_ROTATE_SLOT_PASSWORD => {
            let mut offset = 0;
            let old_password = decode_string(payload, &mut offset)?;
            let new_password = decode_string(payload, &mut offset)?;
            Ok(IpcRequest::RotateSlotPassword {
                old_password,
                new_password,
            })
        }
        OP_RECOVER_AND_SYNC => {
            let mut offset = 0;
            let recovery_secret = decode_string(payload, &mut offset)?;
            let new_system_password = decode_string(payload, &mut offset)?;
            Ok(IpcRequest::RecoverAndSyncWithCurrentPassword {
                recovery_secret,
                new_system_password,
            })
        }
        OP_PING => Ok(IpcRequest::Ping),
        unknown => Err(IpcError::InvalidOpcode(unknown)),
    }
}

/// Encodes an `IpcResponse` into wire format bytes: `[magic (4)][version (1)][status (1)][len (2)][payload]`.
pub fn encode_response(resp: &IpcResponse, out: &mut Vec<u8>) -> IpcResult<()> {
    out.clear();
    out.extend_from_slice(&MAGIC);
    out.push(PROTOCOL_VERSION);

    let (status, mut payload) = match resp {
        IpcResponse::Secret(secret_bytes) => {
            (STATUS_SECRET, secret_bytes.as_slice().to_vec())
        }
        IpcResponse::LockStatus(state) => {
            let code = match state {
                LockState::Uninitialized => 0u8,
                LockState::Locked => 1u8,
                LockState::Unlocked => 2u8,
                LockState::Desynced => 3u8,
            };
            (STATUS_LOCK_STATUS, vec![code])
        }
        IpcResponse::Success => (STATUS_SUCCESS, Vec::new()),
        IpcResponse::Locked => (STATUS_LOCKED, Vec::new()),
        IpcResponse::Desynced => (STATUS_DESYNCED, Vec::new()),
        IpcResponse::Cancelled => (STATUS_CANCELLED, Vec::new()),
        IpcResponse::AccessDenied(msg) => {
            let mut p = Vec::with_capacity(msg.len() + 2);
            encode_string(&mut p, msg)?;
            (STATUS_ACCESS_DENIED, p)
        }
        IpcResponse::Error(msg) => {
            let mut p = Vec::with_capacity(msg.len() + 2);
            encode_string(&mut p, msg)?;
            (STATUS_ERROR, p)
        }
    };

    if payload.len() > MAX_PAYLOAD_SIZE {
        payload.zeroize();
        return Err(IpcError::FrameTooLarge(payload.len(), MAX_PAYLOAD_SIZE));
    }

    out.push(status);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    payload.zeroize();

    Ok(())
}

/// Decodes an `IpcResponse` from status code and payload bytes.
pub fn decode_response(status: u8, payload: &[u8]) -> IpcResult<IpcResponse> {
    match status {
        STATUS_SUCCESS => Ok(IpcResponse::Success),
        STATUS_SECRET => {
            Ok(IpcResponse::Secret(SecretBytes::new(payload.to_vec())))
        }
        STATUS_LOCK_STATUS => {
            if payload.is_empty() {
                return Err(IpcError::MalformedPayload("Missing lock state byte".into()));
            }
            let state = match payload[0] {
                0 => LockState::Uninitialized,
                1 => LockState::Locked,
                2 => LockState::Unlocked,
                3 => LockState::Desynced,
                other => {
                    return Err(IpcError::MalformedPayload(format!(
                        "Unknown lock state: {other}"
                    )))
                }
            };
            Ok(IpcResponse::LockStatus(state))
        }
        STATUS_LOCKED => Ok(IpcResponse::Locked),
        STATUS_DESYNCED => Ok(IpcResponse::Desynced),
        STATUS_CANCELLED => Ok(IpcResponse::Cancelled),
        STATUS_ACCESS_DENIED => {
            let mut offset = 0;
            let msg = decode_string(payload, &mut offset)?;
            Ok(IpcResponse::AccessDenied(msg))
        }
        STATUS_ERROR => {
            let mut offset = 0;
            let msg = decode_string(payload, &mut offset)?;
            Ok(IpcResponse::Error(msg))
        }
        unknown => Err(IpcError::InvalidStatus(unknown)),
    }
}

// ---------------- Helper string framing ----------------

fn encode_string(out: &mut Vec<u8>, s: &str) -> IpcResult<()> {
    let bytes = s.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(IpcError::Serialization("String length exceeds u16 limit".into()));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_string(payload: &[u8], offset: &mut usize) -> IpcResult<String> {
    if *offset + 2 > payload.len() {
        return Err(IpcError::MalformedPayload("Truncated string length prefix".into()));
    }
    let len = u16::from_be_bytes([payload[*offset], payload[*offset + 1]]) as usize;
    *offset += 2;
    if *offset + len > payload.len() {
        return Err(IpcError::MalformedPayload("Truncated string bytes".into()));
    }
    let s = std::str::from_utf8(&payload[*offset..*offset + len])
        .map_err(|e| IpcError::MalformedPayload(format!("Invalid UTF-8 string: {e}")))?
        .to_string();
    *offset += len;
    Ok(s)
}

// ---------------- Async Network Operations ----------------

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    req: &IpcRequest,
) -> IpcResult<()> {
    let mut buf = Vec::with_capacity(128);
    encode_request(req, &mut buf)?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    buf.zeroize();
    Ok(())
}

pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> IpcResult<IpcRequest> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    if header[0..4] != MAGIC {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&header[0..4]);
        return Err(IpcError::InvalidMagic(magic));
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion(header[4]));
    }
    let opcode = header[5];
    let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(IpcError::FrameTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    let req = decode_request(opcode, &payload)?;
    payload.zeroize();
    Ok(req)
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &IpcResponse,
) -> IpcResult<()> {
    let mut buf = Vec::with_capacity(128);
    encode_response(resp, &mut buf)?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    buf.zeroize();
    Ok(())
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> IpcResult<IpcResponse> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;

    if header[0..4] != MAGIC {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&header[0..4]);
        return Err(IpcError::InvalidMagic(magic));
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion(header[4]));
    }
    let status = header[5];
    let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(IpcError::FrameTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    let resp = decode_response(status, &payload)?;
    payload.zeroize();
    Ok(resp)
}

// ---------------- Synchronous Network Operations ----------------

pub fn write_request_sync<W: std::io::Write>(writer: &mut W, req: &IpcRequest) -> IpcResult<()> {
    let mut buf = Vec::with_capacity(128);
    encode_request(req, &mut buf)?;
    writer.write_all(&buf)?;
    writer.flush()?;
    buf.zeroize();
    Ok(())
}

pub fn read_response_sync<R: std::io::Read>(reader: &mut R) -> IpcResult<IpcResponse> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;

    if header[0..4] != MAGIC {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&header[0..4]);
        return Err(IpcError::InvalidMagic(magic));
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion(header[4]));
    }
    let status = header[5];
    let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(IpcError::FrameTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload)?;

    let resp = decode_response(status, &payload)?;
    payload.zeroize();
    Ok(resp)
}

pub fn write_response_sync<W: std::io::Write>(writer: &mut W, resp: &IpcResponse) -> IpcResult<()> {
    let mut buf = Vec::with_capacity(128);
    encode_response(resp, &mut buf)?;
    writer.write_all(&buf)?;
    writer.flush()?;
    buf.zeroize();
    Ok(())
}

pub fn read_request_sync<R: std::io::Read>(reader: &mut R) -> IpcResult<IpcRequest> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header)?;

    if header[0..4] != MAGIC {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&header[0..4]);
        return Err(IpcError::InvalidMagic(magic));
    }
    if header[4] != PROTOCOL_VERSION {
        return Err(IpcError::UnsupportedVersion(header[4]));
    }
    let opcode = header[5];
    let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(IpcError::FrameTooLarge(payload_len, MAX_PAYLOAD_SIZE));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload)?;

    let req = decode_request(opcode, &payload)?;
    payload.zeroize();
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_v2_request_roundtrip() {
        let req = IpcRequest::GetApplicationSecret {
            namespace: "atrium.portal.Secret/v1".to_string(),
            subject: "org.mozilla.Firefox".to_string(),
            purpose: "master-secret".to_string(),
        };

        let mut out = Vec::new();
        encode_request(&req, &mut out).unwrap();
        assert_eq!(&out[0..4], b"SIGL");
        assert_eq!(out[4], 2);
        assert_eq!(out[5], OP_GET_APPLICATION_SECRET);

        let decoded = decode_request(out[5], &out[8..]).unwrap();
        match decoded {
            IpcRequest::GetApplicationSecret {
                namespace,
                subject,
                purpose,
            } => {
                assert_eq!(namespace, "atrium.portal.Secret/v1");
                assert_eq!(subject, "org.mozilla.Firefox");
                assert_eq!(purpose, "master-secret");
            }
            _ => panic!("Wrong variant decoded"),
        }
    }

    #[test]
    fn test_wire_v2_response_roundtrip() {
        let secret = SecretBytes::new(vec![42u8; 32]);
        let resp = IpcResponse::Secret(secret);

        let mut out = Vec::new();
        encode_response(&resp, &mut out).unwrap();
        assert_eq!(&out[0..4], b"SIGL");
        assert_eq!(out[4], 2);
        assert_eq!(out[5], STATUS_SECRET);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 32);

        let decoded = decode_response(out[5], &out[8..]).unwrap();
        match decoded {
            IpcResponse::Secret(bytes) => {
                assert_eq!(bytes.as_slice(), &[42u8; 32]);
            }
            _ => panic!("Wrong variant decoded"),
        }
    }
}
