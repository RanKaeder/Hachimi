use std::{
    fs,
    io::{
        Write,
        Seek,
        SeekFrom
    },
    path::Path,
    sync::{
        atomic::{self, AtomicBool},
        mpsc,
        Arc,
        Mutex
    }
};
use std::thread;
use thread_priority::{ThreadBuilderExt, ThreadPriority};

use arc_swap::ArcSwap;
use serde::de::DeserializeOwned;

use super::Error;

pub struct AsyncRequest<T: Send + Sync> {
    request: ureq::Request,
    map_fn: fn(ureq::Response) -> Result<T, Error>,
    running: AtomicBool,
    pub result: ArcSwap<Option<Result<T, Error>>>
}

impl<T: Send + Sync + 'static> AsyncRequest<T> {
    pub fn new(request: ureq::Request, map_fn: fn(ureq::Response) -> Result<T, Error>) -> Self {
        AsyncRequest {
            request,
            map_fn,
            running: AtomicBool::new(false),
            result: ArcSwap::default()
        }
    }

    pub fn call(self: Arc<Self>) {
        self.result.store(Arc::new(None));
        self.running.store(true, atomic::Ordering::Release);
        std::thread::spawn(move || {
            let res = match self.request.clone().call() {
                Ok(v) => (self.map_fn)(v),
                Err(e) => Err(Error::from(e))
            };
            self.result.store(Arc::new(Some(res)));
            self.running.store(false, atomic::Ordering::Release);
        });
    }

    pub fn running(&self) -> bool {
        self.running.load(atomic::Ordering::Acquire)
    }
}

impl<T: Send + Sync + 'static + DeserializeOwned> AsyncRequest<T> {
    pub fn with_json_response(request: ureq::Request) -> AsyncRequest<T> {
        AsyncRequest::new(request, |res|
            Ok(serde_json::from_str(&res.into_string()?)?)
        )
    }
}

pub fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let res = ureq::get(url).call()?;
    Ok(serde_json::from_str(&res.into_string()?)?)
}

pub fn get_github_json<T: DeserializeOwned>(url: &str) -> Result<T, Error> {
    let res = ureq::get(url)
        .set("Accept", "application/vnd.github+json")
        .set("X-GitHub-Api-Version", "2022-11-28")
        .call()?;
    Ok(serde_json::from_str(&res.into_string()?)?)
}

pub fn download_file_parallel(url: &str, file_path: &Path, num_threads: usize,
    min_chunk_size: u64, chunk_size: usize, progress_callback: Arc<dyn Fn(usize) + Send + Sync>
) -> Result<(), Error> {
    let agent = ureq::Agent::new();
    let res = agent.head(url).call()?;

    let content_length = res.header("Content-Length").and_then(|s| s.parse::<u64>().ok());
    let accepts_ranges = res.header("Accept-Ranges").map_or(false, |v| v == "bytes");

    let mut actual_length = 0u64;
    let use_parallel = if let Some(length) = content_length {
        actual_length = length;
        accepts_ranges && length > min_chunk_size
    } else {
        false
    };

    if use_parallel {
        let mut downloaded_file = fs::File::create(file_path)?;
        downloaded_file.set_len(actual_length)?;
        drop(downloaded_file);

        let chunk_size_per_thread = (actual_length / num_threads as u64).max(min_chunk_size);
        let num_chunks = (actual_length + chunk_size_per_thread - 1) / chunk_size_per_thread;

        let fatal_error = Arc::new(Mutex::new(None::<Error>));
        let stop_signal = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<(u64, u64)>();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let agent_clone = agent.clone();
            let url_clone = url.to_string();
            let path_clone = file_path.to_path_buf();
            let receiver_clone = Arc::clone(&receiver);
            let progress_callback_clone = Arc::clone(&progress_callback);
            let fatal_error_clone = Arc::clone(&fatal_error);
            let stop_signal_clone = Arc::clone(&stop_signal);

            let handle = thread::Builder::new()
                .name("downloader_chunk".into())
                .spawn_with_priority(ThreadPriority::Min, move |result| {
                    if result.is_err() { warn!("Failed to set downloader thread priority."); }
                    let mut file = match fs::File::options().write(true).open(&path_clone) {
                        Ok(f) => f,
                        Err(e) => { *fatal_error_clone.lock().unwrap() = Some(e.into()); return; }
                    };
                    let mut buffer = vec![0u8; chunk_size];
                    while let Ok((start, end)) = receiver_clone.lock().unwrap().recv() {
                        if stop_signal_clone.load(atomic::Ordering::Relaxed) { break; }
                        let range_header = format!("bytes={}-{}", start, end);
                        let result = (|| -> Result<(), Error> {
                            let res = agent_clone.get(&url_clone).set("Range", &range_header).call()?;
                            let mut reader = res.into_reader();
                            file.seek(SeekFrom::Start(start))?;
                            loop {
                                let bytes_read = reader.read(&mut buffer)?;
                                if bytes_read == 0 { break; }
                                file.write_all(&buffer[..bytes_read])?;
                                progress_callback_clone(bytes_read);
                                if stop_signal_clone.load(atomic::Ordering::Relaxed) {
                                    return Err(Error::RuntimeError("Download cancelled".into()));
                                }
                            }
                            Ok(())
                        })();
                        if let Err(e) = result {
                            *fatal_error_clone.lock().unwrap() = Some(e);
                            stop_signal_clone.store(true, atomic::Ordering::Relaxed);
                            break;
                        }
                    }
                }).unwrap();
            handles.push(handle);
        }

        for i in 0..num_chunks {
            let start = i * chunk_size_per_thread;
            let end = (start + chunk_size_per_thread - 1).min(actual_length - 1);
            if sender.send((start, end)).is_err() { break; }
        }
        drop(sender);

        for handle in handles {
            handle.join().unwrap();
        }

        if let Some(e) = fatal_error.lock().unwrap().take() { return Err(e); }
        let downloaded_file = fs::File::options().write(true).open(file_path)?;
        downloaded_file.sync_data()?;
    } else {
        debug!("Using single-threaded download for: {}", url);
        let res = agent.get(url).call()?;
        let mut file = fs::File::create(file_path)?;
        let mut buffer = vec![0u8; chunk_size];

        download_file_buffered(res, &mut file, &mut buffer, |bytes_slice| {
            progress_callback(bytes_slice.len());
        })?;
        file.sync_data()?;
    }
    Ok(())
}

pub fn download_file_buffered(res: ureq::Response, file: &mut std::fs::File, buffer: &mut [u8], mut add_bytes: impl FnMut(&[u8])) -> Result<(), Error> {
    let mut reader = res.into_reader();
    let mut buffer_pos = 0usize;
    loop {
        let read_bytes = reader.read(&mut buffer[buffer_pos..])?;

        let prev_buffer_pos = buffer_pos;
        buffer_pos += read_bytes;
        add_bytes(&buffer[prev_buffer_pos..buffer_pos]);

        if buffer_pos == buffer.len() {
            buffer_pos = 0;
            let written = file.write(&buffer)?;
            if written != buffer.len() {
                return Err(Error::OutOfDiskSpace);
            }
        }

        if read_bytes == 0 {
            break;
        }
    }

    // Download finished, flush the buffer
    if buffer_pos != 0 {
        let written = file.write(&buffer[..buffer_pos])?;
        if written != buffer_pos {
            return Err(Error::OutOfDiskSpace);
        }
    }

    Ok(())
}