#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tauri::command;
use tokio::sync::Semaphore;
#[cfg(not(target_os = "windows"))]
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tauri::Window;
use memmap2::Mmap;
use tauri::async_runtime::spawn_blocking;
use serde_json::json;
#[allow(unused_imports)]
use md5::{Md5, Digest as Md5Digest};
#[allow(unused_imports)]
use sha1::{Sha1, Digest as Sha1Digest};
#[allow(unused_imports)]
use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use blake3::Hasher as Blake3Hasher;
use xxhash_rust::xxh3::Xxh3 as XxHash3;
use sequoia_openpgp::{
    cert::Cert,
    parse::Parse,
    parse::stream::{DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper, VerificationResult},
    policy::StandardPolicy,
    KeyHandle,
};

struct AppState {
    cancel: Arc<AtomicBool>,
}

// ULTIMATE PERFORMANCE: BLAKE3 multithreading + optimized single-pass for others
async fn fast_calculate_checksums_mmap(window: Window, cancel: Arc<AtomicBool>, file_path: String, algorithms: Vec<String>, _total: u64) -> Result<HashMap<String, String>, String> {
    let path = file_path.clone();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<i32>();
    let file_clone = file_path.clone();
    let cancel_clone = cancel.clone();
    let algs = algorithms.clone();

    let handle = spawn_blocking(move || -> Result<HashMap<String, String>, String> {
        // BREAKTHROUGH 1: Use BLAKE3's multithreaded memory-mapped hashing first!
        let mut blake3_hash = None;
        if algs.contains(&"blake3".to_string()) {
            let mut hasher = Blake3Hasher::new();
            // This is the magic: BLAKE3's built-in multithreaded memory-mapped hashing
            hasher.update_mmap_rayon(&path).map_err(|e| e.to_string())?;
            blake3_hash = Some(format!("{}", hasher.finalize().to_hex()));
        }

        // If we only need BLAKE3, we're done!
        if blake3_hash.is_some() && algs.len() == 1 {
            let mut results = HashMap::new();
            results.insert("blake3".to_string(), blake3_hash.unwrap());
            return Ok(results);
        }

        // BREAKTHROUGH 2: For other algorithms, use memory mapping with maximum optimization
        let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        let mmap = unsafe { Mmap::map(&file).map_err(|e| e.to_string())? };

        // Initialize hashers for remaining algorithms
        let mut md5_hasher = if algs.contains(&"md5".to_string()) { Some(md5::Md5::new()) } else { None };
        let mut sha1_hasher = if algs.contains(&"sha1".to_string()) { Some(sha1::Sha1::new()) } else { None };
        let mut sha256_hasher = if algs.contains(&"sha256".to_string()) { Some(sha2::Sha256::new()) } else { None };
        let mut sha512_hasher = if algs.contains(&"sha512".to_string()) { Some(sha2::Sha512::new()) } else { None };
        let mut xxhash3_hasher = if algs.contains(&"xxhash3".to_string()) { Some(XxHash3::new()) } else { None };

        let len = mmap.len();
    // Use larger chunks for better throughput on NVMe/SATA
    let chunk_size = 4 * 1024 * 1024; // 4MB chunks
        let mut offset: usize = 0;
        let mut last_progress = 0;

        // OPTIMIZED: Single-pass through memory with maximum chunk size
        while offset < len {
            if cancel_clone.load(Ordering::SeqCst) {
                return Err("Cancelled".to_string());
            }
            
            let end = std::cmp::min(offset + chunk_size, len);
            let slice = &mmap[offset..end];
            
            // Update ALL hashers with the SAME chunk - maximum efficiency
            if let Some(ref mut h) = md5_hasher { h.update(slice); }
            if let Some(ref mut h) = sha1_hasher { h.update(slice); }
            if let Some(ref mut h) = sha256_hasher { h.update(slice); }
            if let Some(ref mut h) = sha512_hasher { h.update(slice); }
            if let Some(ref mut h) = xxhash3_hasher { h.update(slice); }

            offset = end;
            
            // Progress reporting every ~5% to balance responsiveness and overhead
            let progress = ((offset as f64 / len as f64) * 100.0) as i32;
            if progress >= last_progress + 5 {
                last_progress = progress;
                let _ = tx.send(progress);
            }
        }

        // Finalize all results
        let mut results = HashMap::new();
        if let Some(h) = md5_hasher { results.insert("md5".to_string(), format!("{:x}", h.finalize())); }
        if let Some(h) = sha1_hasher { results.insert("sha1".to_string(), format!("{:x}", h.finalize())); }
        if let Some(h) = sha256_hasher { results.insert("sha256".to_string(), format!("{:x}", h.finalize())); }
        if let Some(h) = sha512_hasher { results.insert("sha512".to_string(), format!("{:x}", h.finalize())); }
        if let Some(h) = xxhash3_hasher { results.insert("xxhash3".to_string(), format!("{:x}", h.digest())); }
        if let Some(blake3) = blake3_hash { results.insert("blake3".to_string(), blake3); }

        Ok(results)
    });

    // Minimal progress forwarding
    let window_clone = window.clone();
    let map_file = file_clone.clone();
    tokio::spawn(async move {
        while let Some(progress) = rx.recv().await {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            let _ = window_clone.emit("hash-progress", json!({ "file": map_file, "percent": progress }));
        }
    });

    match handle.await.map_err(|e| e.to_string())? {
        Ok(res) => {
            let _ = window.emit("hash-progress", json!({ "file": file_path, "percent": 100 }));
            Ok(res)
        }
        Err(e) => Err(e),
    }
}

// internal worker that can be called by commands and spawned tasks
async fn do_calculate_checksums(window: Window, cancel: Arc<AtomicBool>, file_path: String, algorithms: Vec<String>) -> Result<HashMap<String, String>, String> {
    // Open file and get total size for progress reporting
    let metadata = tokio::fs::metadata(&file_path).await.map_err(|e| e.to_string())?;
    let total = metadata.len();

    // Use memory-mapped path for smaller files too - Python doesn't differentiate much
    const MMAP_THRESHOLD: u64 = 1024 * 1024; // 1 MB - much lower threshold like Python
    if total >= MMAP_THRESHOLD {
        // Try optimized mmap fast path
        if let Ok(results) = fast_calculate_checksums_mmap(window.clone(), cancel.clone(), file_path.clone(), algorithms.clone(), total).await {
            return Ok(results);
        }
        // Fall through to streaming path on error or unsupported platform
    }

    // Prepare incremental hashers based on requested algorithms
    let mut has_md5 = false;
    let mut has_sha1 = false;
    let mut has_sha256 = false;
    let mut has_sha512 = false;
    let mut has_blake3 = false;
    let mut has_xxhash3 = false;

    for alg in &algorithms {
        match alg.as_str() {
            "md5" => has_md5 = true,
            "sha1" => has_sha1 = true,
            "sha256" => has_sha256 = true,
            "sha512" => has_sha512 = true,
            "blake3" => has_blake3 = true,
            "xxhash3" => has_xxhash3 = true,
            _ => {}
        }
    }

    let mut md5_hasher = if has_md5 { Some(Md5::new()) } else { None };
    let mut sha1_hasher = if has_sha1 { Some(Sha1::new()) } else { None };
    let mut sha256_hasher = if has_sha256 { Some(Sha256::new()) } else { None };
    let mut sha512_hasher = if has_sha512 { Some(Sha512::new()) } else { None };
    let mut blake3_hasher = if has_blake3 { Some(Blake3Hasher::new()) } else { None };
    let mut xxhash3_hasher = if has_xxhash3 { Some(XxHash3::new()) } else { None };

    // Larger buffer improves throughput on fast disks (kept under L3 limits)
    let mut buf = vec![0u8; 1024 * 1024]; // 1MB buffer
    let mut read_total: u64 = 0;
    let mut last_emitted_percent: i32 = -1;

    // open file for streaming read fallback, with sequential scan hint on Windows
    #[cfg(target_os = "windows")]
    let mut file = {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_READ};
        let std_file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
            .open(&file_path)
            .map_err(|e| e.to_string())?;
        tokio::fs::File::from_std(std_file)
    };
    #[cfg(not(target_os = "windows"))]
    let mut file = File::open(&file_path).await.map_err(|e| e.to_string())?;

    loop {
        let n = file.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 { break; }
        // check for cancellation
        if cancel.load(Ordering::SeqCst) {
            let _ = window.emit("hash-progress", json!({ "file": file_path, "bytes_read": read_total, "total": total, "percent": read_total as f64 / total as f64 * 100.0 }));
            return Err("Cancelled".to_string());
        }
        read_total += n as u64;

        let chunk = &buf[..n];
        if let Some(ref mut h) = md5_hasher { h.update(chunk); }
        if let Some(ref mut h) = sha1_hasher { h.update(chunk); }
        if let Some(ref mut h) = sha256_hasher { h.update(chunk); }
        if let Some(ref mut h) = sha512_hasher { h.update(chunk); }
        if let Some(ref mut h) = blake3_hasher { h.update(chunk); }
        if let Some(ref mut h) = xxhash3_hasher { h.update(chunk); }

        // Emit progress every ~2% to reduce event overhead
        let percent_f = if total > 0 { ((read_total as f64 / total as f64) * 100.0).min(100.0) } else { 0.0 };
        let percent_i = percent_f.floor() as i32;
        if percent_i - last_emitted_percent >= 2 {
            last_emitted_percent = percent_i;
            let _ = window.emit("hash-progress", json!({ "file": file_path, "bytes_read": read_total, "total": total, "percent": percent_f }));
        }
    }

    let mut results = HashMap::new();
    if has_md5 {
        if let Some(h) = md5_hasher {
            results.insert("md5".to_string(), format!("{:x}", h.finalize()));
        }
    }
    if has_sha1 {
        if let Some(h) = sha1_hasher {
            results.insert("sha1".to_string(), format!("{:x}", h.finalize()));
        }
    }
    if has_sha256 {
        if let Some(h) = sha256_hasher {
            results.insert("sha256".to_string(), format!("{:x}", h.finalize()));
        }
    }
    if has_sha512 {
        if let Some(h) = sha512_hasher {
            results.insert("sha512".to_string(), format!("{:x}", h.finalize()));
        }
    }
    if has_blake3 {
        if let Some(h) = blake3_hasher {
            results.insert("blake3".to_string(), format!("{}", h.finalize().to_hex()));
        }
    }
    if has_xxhash3 {
        if let Some(h) = xxhash3_hasher {
            results.insert("xxhash3".to_string(), format!("{:x}", h.digest()));
        }
    }

    // Ensure we send a final 100% progress (if not already sent)
    if last_emitted_percent != 100 {
        let _ = window.emit("hash-progress", json!({ "file": file_path, "bytes_read": read_total, "total": total, "percent": 100.0 }));
    }

    Ok(results)
}

#[command]
async fn calculate_checksums(window: Window, state: tauri::State<'_, AppState>, file_path: String, algorithms: Vec<String>) -> Result<HashMap<String, String>, String> {
    // reset cancel flag at start of a new calculation
    state.cancel.store(false, Ordering::SeqCst);
    do_calculate_checksums(window, state.cancel.clone(), file_path, algorithms).await
}

// Helper command used by the frontend to validate whether a given path is a regular file.
#[command]
async fn is_path_file(path: String) -> Result<bool, String> {
    match tokio::fs::metadata(&path).await {
        Ok(md) => Ok(md.is_file()),
        Err(e) => Err(e.to_string()),
    }
}

#[command]
fn cancel_hashing(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.cancel.store(true, Ordering::SeqCst);
    Ok(())
}

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FileData {
    name: String,
    path: String,
    md5: String,
    sha1: String,
    sha256: String,
    sha512: String,
    blake3: String,
    xxhash3: String,
}

#[command]
async fn scan_folder(window: Window, state: tauri::State<'_, AppState>, folder_path: String, include_subfolders: bool, include_hidden: bool, algorithms: Vec<String>) -> Result<Vec<FileData>, String> {
    // First, collect files to process
    let mut files_to_process: Vec<String> = Vec::new();
    let mut folders_to_scan = vec![folder_path];

    while let Some(folder) = folders_to_scan.pop() {
        let mut entries = tokio::fs::read_dir(folder).await.map_err(|e| e.to_string())?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| e.to_string())? {
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
                if !include_hidden && file_name.starts_with('.') {
                    continue;
                }
                files_to_process.push(path.to_str().unwrap().to_string());
            } else if path.is_dir() && include_subfolders {
                folders_to_scan.push(path.to_str().unwrap().to_string());
            }
        }
    }

    // Process files concurrently with a semaphore to limit parallelism
    let sem = Arc::new(Semaphore::new(8)); // Increased concurrency from 4 to 8
    let mut handles = Vec::new();

    for file_path in files_to_process {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let win = window.clone();
        let cancel_flag = state.cancel.clone();
        let file_path_clone = file_path.clone();
        let algorithms_clone = algorithms.clone(); // Clone algorithms for each task

        let handle = tokio::spawn(async move {
            // permit is dropped at end of scope to release semaphore
            let _permit = permit;
            match do_calculate_checksums(win, cancel_flag.clone(), file_path_clone.clone(), algorithms_clone).await {
                Ok(checksums) => Ok((file_path_clone, checksums)),
                Err(e) => Err((file_path_clone, e)),
            }
        });

        handles.push(handle);
    }

    let mut files_data = Vec::new();
    for h in handles {
        if let Ok(res) = h.await {
            match res {
                Ok((path, checksums)) => {
                    let file_name = std::path::Path::new(&path).file_name().unwrap().to_str().unwrap().to_string();
                    files_data.push(FileData {
                        name: file_name,
                        path: path.clone(),
                        md5: checksums.get("md5").unwrap_or(&"".to_string()).to_string(),
                        sha1: checksums.get("sha1").unwrap_or(&"".to_string()).to_string(),
                        sha256: checksums.get("sha256").unwrap_or(&"".to_string()).to_string(),
                        sha512: checksums.get("sha512").unwrap_or(&"".to_string()).to_string(),
                        blake3: checksums.get("blake3").unwrap_or(&"".to_string()).to_string(),
                        xxhash3: checksums.get("xxhash3").unwrap_or(&"".to_string()).to_string(),
                    });
                }
                Err((_path, _err)) => {
                    // ignore individual file errors for now
                }
            }
        }
    }

    Ok(files_data)
}

#[command]
async fn save_report(file_path: String, data: String, format: String) -> Result<(), String> {
    if let Some(parent) = Path::new(&file_path).parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
        }
    }

    match format.as_str() {
        "json" => {
            let mut file = tokio::fs::File::create(&file_path).await.map_err(|e| e.to_string())?;
            tokio::io::AsyncWriteExt::write_all(&mut file, data.as_bytes()).await.map_err(|e| e.to_string())?;
        }
        "csv" => {
            let mut wtr = csv::Writer::from_path(&file_path).map_err(|e| e.to_string())?;
            let records: Vec<FileData> = serde_json::from_str(&data).map_err(|e| e.to_string())?;
            for record in records {
                wtr.serialize(record).map_err(|e| e.to_string())?;
            }
            wtr.flush().map_err(|e| e.to_string())?;
        }
        "txt" => {
            let mut file = tokio::fs::File::create(&file_path).await.map_err(|e| e.to_string())?;
            tokio::io::AsyncWriteExt::write_all(&mut file, data.as_bytes()).await.map_err(|e| e.to_string())?;
        }
        _ => return Err("Unsupported format".to_string()),
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct GpgKeyInfo {
    fingerprint: String,
    user_ids: Vec<String>,
}

#[derive(serde::Serialize)]
struct GpgVerificationSummary {
    is_valid: bool,
    fingerprint: String,
    user_ids: Vec<String>,
    messages: Vec<String>,
}

struct GpgVerificationHelper {
    cert: Cert,
    messages: Vec<String>,
    verified: bool,
}

impl VerificationHelper for GpgVerificationHelper {
    type Response = GpgVerificationSummary;

    fn get_certs(&mut self, _ids: &[KeyHandle]) -> sequoia_openpgp::Result<Vec<Cert>> {
        Ok(vec![self.cert.clone()])
    }

    fn check(&mut self, structure: &MessageStructure) -> sequoia_openpgp::Result<()> {
        for layer in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    match result {
                        Ok(VerificationResult::GoodChecksum { .. }) => {
                            self.verified = true;
                            self.messages.push("Signature verified successfully".to_string());
                        }
                        Ok(other) => {
                            self.messages.push(format!("Signature status: {:?}", other));
                        }
                        Err(err) => {
                            self.messages.push(format!("Verification error: {err}"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(self, _structure: MessageStructure) -> sequoia_openpgp::Result<Self::Response> {
        let fingerprint = self.cert.fingerprint().to_string();
        let user_ids = self
            .cert
            .userids()
            .map(|uid| String::from_utf8_lossy(uid.userid()).to_string())
            .collect::<Vec<_>>();

        Ok(GpgVerificationSummary {
            is_valid: self.verified,
            fingerprint,
            user_ids,
            messages: self.messages,
        })
    }
}

#[command]
async fn inspect_gpg_key(path: String) -> Result<GpgKeyInfo, String> {
    let data = tokio::fs::read(&path).await.map_err(|e| e.to_string())?;
    let mut cursor = std::io::Cursor::new(data);
    let cert = Cert::from_reader(&mut cursor).map_err(|e| e.to_string())?;

    let fingerprint = cert.fingerprint().to_string();
    let user_ids = cert
        .userids()
        .map(|uid| String::from_utf8_lossy(uid.userid()).to_string())
        .collect::<Vec<_>>();

    Ok(GpgKeyInfo { fingerprint, user_ids })
}

#[command]
async fn verify_gpg_signature(file_path: String, signature_path: String, public_key_path: String) -> Result<GpgVerificationSummary, String> {
    let policy = StandardPolicy::new();

    let result = tauri::async_runtime::spawn_blocking(move || -> Result<GpgVerificationSummary, String> {
        let pub_data = std::fs::read(&public_key_path).map_err(|e| e.to_string())?;
        let sig_data = std::fs::read(&signature_path).map_err(|e| e.to_string())?;
        let mut pub_cursor = std::io::Cursor::new(pub_data);
        let cert = Cert::from_reader(&mut pub_cursor).map_err(|e| e.to_string())?;

        let helper = GpgVerificationHelper {
            cert,
            messages: Vec::new(),
            verified: false,
        };

        let builder = DetachedVerifierBuilder::from_bytes(&sig_data).map_err(|e| e.to_string())?;
        let mut verifier = builder
            .with_policy(&policy, None, helper)
            .map_err(|e| e.to_string())?;

        let mut file = std::fs::File::open(&file_path).map_err(|e| e.to_string())?;
        std::io::copy(&mut file, &mut verifier).map_err(|e| e.to_string())?;
        let summary = verifier.finish().map_err(|e| e.to_string())?;
        Ok(summary)
    })
    .await
    .map_err(|e| e.to_string())?;

    result
}

#[command]
async fn verify_hash(expected_hash: String, calculated_hashes: HashMap<String, String>) -> bool {
    for (_, hash) in calculated_hashes {
        if expected_hash == hash {
            return true;
        }
    }
    false
}

#[derive(serde::Serialize, serde::Deserialize)]
struct UpdateInfo {
    version: String,
    url: String,
    body: String,
}

#[command]
async fn check_for_updates() -> Result<UpdateInfo, String> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.github.com/repos/oop7/rhashsum/releases/latest")
        .header("User-Agent", "rust-hash-sum")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let data: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;

    let latest_version = data["tag_name"].as_str().unwrap_or("").trim_start_matches('v');
    let current_version = env!("CARGO_PKG_VERSION");

    if latest_version > current_version {
        Ok(UpdateInfo {
            version: latest_version.to_string(),
            url: data["html_url"].as_str().unwrap_or("").to_string(),
            body: data["body"].as_str().unwrap_or("").to_string(),
        })
    } else {
        Err("No new version available".to_string())
    }
}

fn main() {
    let state = AppState { cancel: Arc::new(AtomicBool::new(false)) };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            greet,
            calculate_checksums,
            scan_folder,
            save_report,
            verify_hash,
            inspect_gpg_key,
            verify_gpg_signature,
            check_for_updates,
            is_path_file,
            cancel_hashing,
        ])
        .run(tauri::generate_context!()) 
        .expect("error while running tauri application");
}