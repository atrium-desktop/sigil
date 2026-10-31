use sigil_vault::FileVaultStore;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

#[test]
fn test_vault_cross_process_flock_concurrency() {
    let temp_dir = std::env::temp_dir().join(format!("sigil_flock_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);

    let store = FileVaultStore::new(temp_dir.clone());

    // 1. Acquire exclusive lock
    let lock_guard = store.acquire_exclusive_lock().expect("Lock should succeed");

    // 2. Simulate concurrent process trying to lock the same file non-blockingly
    let lock_path = store.lock_path();
    let file_proc2 = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("Open lock file from proc 2");

    let fd2 = file_proc2.as_raw_fd();
    let ret = unsafe { libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(
        ret, -1,
        "Concurrent non-blocking flock must fail when held by lock_guard"
    );
    let err = std::io::Error::last_os_error();
    assert!(
        err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
    );

    // 3. Drop lock_guard (release lock)
    drop(lock_guard);

    // 4. Now second attempt must succeed
    let ret2 = unsafe { libc::flock(fd2, libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(ret2, 0, "Flock must succeed after initial guard is dropped");
    unsafe {
        let _ = libc::flock(fd2, libc::LOCK_UN);
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}
