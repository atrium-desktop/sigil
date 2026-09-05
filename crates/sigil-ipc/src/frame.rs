use crate::error::{IpcError, IpcResult};
use crate::protocol::{IpcRequest, IpcResponse};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME_SIZE: usize = 64 * 1024; // 64 KB limit for safety

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    req: &IpcRequest,
) -> IpcResult<()> {
    let payload = serde_json::to_vec(req)
        .map_err(|e| IpcError::Serialization(e.to_string()))?;

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> IpcResult<IpcRequest> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge(len, MAX_FRAME_SIZE));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    let req: IpcRequest = serde_json::from_slice(&buf)
        .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    Ok(req)
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    resp: &IpcResponse,
) -> IpcResult<()> {
    let payload = serde_json::to_vec(resp)
        .map_err(|e| IpcError::Serialization(e.to_string()))?;

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> IpcResult<IpcResponse> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge(len, MAX_FRAME_SIZE));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;

    let resp: IpcResponse = serde_json::from_slice(&buf)
        .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    Ok(resp)
}

pub fn write_request_sync<W: std::io::Write>(writer: &mut W, req: &IpcRequest) -> IpcResult<()> {
    let payload = serde_json::to_vec(req)
        .map_err(|e| IpcError::Serialization(e.to_string()))?;

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_response_sync<R: std::io::Read>(reader: &mut R) -> IpcResult<IpcResponse> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge(len, MAX_FRAME_SIZE));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;

    let resp: IpcResponse = serde_json::from_slice(&buf)
        .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    Ok(resp)
}

pub fn write_response_sync<W: std::io::Write>(writer: &mut W, resp: &IpcResponse) -> IpcResult<()> {
    let payload = serde_json::to_vec(resp)
        .map_err(|e| IpcError::Serialization(e.to_string()))?;

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_request_sync<R: std::io::Read>(reader: &mut R) -> IpcResult<IpcRequest> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge(len, MAX_FRAME_SIZE));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;

    let req: IpcRequest = serde_json::from_slice(&buf)
        .map_err(|e| IpcError::Deserialization(e.to_string()))?;

    Ok(req)
}
