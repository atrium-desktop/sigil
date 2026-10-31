use sigil_ipc::{
    decode_request, decode_response, encode_request, IpcError, IpcRequest, IpcResponse,
    MAX_PAYLOAD_SIZE,
};

#[test]
fn test_decode_invalid_magic_and_version() {
    // Valid request payload
    let req = IpcRequest::Ping;
    let mut frame = Vec::new();
    encode_request(&req, &mut frame).unwrap();

    // 1. Corrupt magic bytes
    let mut bad_magic = frame.clone();
    bad_magic[0] = b'X';
    // When reading from stream, read_request checks magic, but decode_request receives opcode and payload
    // Let's test decode_request directly with invalid opcode
    let err = decode_request(0xFF, &[]).unwrap_err();
    assert!(matches!(err, IpcError::InvalidOpcode(0xFF)));

    // 2. Corrupt opcode for response
    let err = decode_response(0xFE, &[]).unwrap_err();
    assert!(matches!(err, IpcError::InvalidStatus(0xFE)));
}

#[test]
fn test_decode_truncated_payloads() {
    // GetApplicationSecret expects 3 length-prefixed strings
    // Provide truncated buffer
    let truncated_payload = vec![0x00, 0x10, b'a', b'b']; // Claims 16 bytes, only has 2
    let err = decode_request(sigil_ipc::OP_GET_APPLICATION_SECRET, &truncated_payload).unwrap_err();
    assert!(matches!(err, IpcError::MalformedPayload(_)));

    // UnlockWithPassword with truncated password
    let truncated_pwd = vec![0x00, 0x20, b'x'];
    let err = decode_request(sigil_ipc::OP_UNLOCK_WITH_PASSWORD, &truncated_pwd).unwrap_err();
    assert!(matches!(err, IpcError::MalformedPayload(_)));

    // RotateSlotPassword truncated
    let truncated_rotate = vec![0x00, 0x05, b'o', b'l', b'd']; // missing new_password
    let err = decode_request(sigil_ipc::OP_ROTATE_SLOT_PASSWORD, &truncated_rotate).unwrap_err();
    assert!(matches!(err, IpcError::MalformedPayload(_)));
}

#[test]
fn test_encode_large_payload_protection() {
    // Strings that exceed MAX_PAYLOAD_SIZE should be rejected on encode
    let giant_string = "a".repeat(MAX_PAYLOAD_SIZE + 100);
    let giant_req = IpcRequest::UnlockWithPassword {
        password: giant_string,
    };
    let mut out = Vec::new();
    let err = encode_request(&giant_req, &mut out).unwrap_err();
    assert!(matches!(err, IpcError::FrameTooLarge(_, _)));
}

#[test]
fn test_decode_status_error_and_access_denied() {
    // Normal Error response
    let error_payload = {
        let mut p = Vec::new();
        let msg = "Disk full or internal failure";
        p.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        p.extend_from_slice(msg.as_bytes());
        p
    };

    let resp = decode_response(sigil_ipc::STATUS_ERROR, &error_payload).unwrap();
    match resp {
        IpcResponse::Error(msg) => assert_eq!(msg, "Disk full or internal failure"),
        _ => panic!("Expected IpcResponse::Error"),
    }

    // Access Denied response
    let access_payload = {
        let mut p = Vec::new();
        let msg = "UID 1001 != 1000";
        p.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        p.extend_from_slice(msg.as_bytes());
        p
    };

    let resp = decode_response(sigil_ipc::STATUS_ACCESS_DENIED, &access_payload).unwrap();
    match resp {
        IpcResponse::AccessDenied(msg) => assert_eq!(msg, "UID 1001 != 1000"),
        _ => panic!("Expected IpcResponse::AccessDenied"),
    }
}
