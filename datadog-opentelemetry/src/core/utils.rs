// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt,
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Duration,
};

pub struct WorkerHandle {
    join_handle: Mutex<Option<thread::JoinHandle<()>>>,
    shutdown_finished: Arc<ShutdownSignaler>,
}

impl WorkerHandle {
    pub fn new(shutdown_finished: Arc<ShutdownSignaler>, handle: thread::JoinHandle<()>) -> Self {
        Self {
            join_handle: Mutex::new(Some(handle)),
            shutdown_finished,
        }
    }

    pub fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), WorkerError> {
        let Some(handle) = self
            .join_handle
            .lock()
            .map_err(|_| {
                crate::dd_error!("RemoteConfigClient.wait_for_shutdown: handle mutex poisoned");
                WorkerError::HandleMutexPoisoned
            })?
            .take()
        else {
            return Ok(());
        };
        self.shutdown_finished.wait_for_shutdown(timeout)?;
        handle.join().map_err(|e| {
            let err = if let Some(e) = e.downcast_ref::<&'static str>() {
                e
            } else if let Some(e) = e.downcast_ref::<String>() {
                e
            } else {
                "unknown panic type"
            };
            crate::dd_error!(
                "RemoteConfigClient.wait_for_shutdown: Worker panicked: {}",
                err
            );
            WorkerError::WorkerPanicked(err.to_string())
        })?;
        Ok(())
    }
}

pub enum WorkerError {
    ShutdownTimedOut,
    HandleMutexPoisoned,
    WorkerPanicked(String),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandleMutexPoisoned => write!(f, "handle mutex poisoned"),
            Self::WorkerPanicked(msg) => write!(f, "remote config worker panicked: {}", msg),
            Self::ShutdownTimedOut => write!(f, "shutdown timed out"),
        }
    }
}

#[derive(Default)]
pub struct ShutdownSignaler {
    shutdown_finished: Mutex<bool>,
    shutdown_condvar: Condvar,
}

impl ShutdownSignaler {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            shutdown_finished: Mutex::new(false),
            shutdown_condvar: Condvar::new(),
        })
    }

    pub fn signal_shutdown(&self) {
        let mut finished = self.shutdown_finished.lock().unwrap();
        *finished = true;
        self.shutdown_condvar.notify_all();
    }

    fn wait_for_shutdown(&self, timeout: Duration) -> Result<(), WorkerError> {
        let Ok(finished) = self.shutdown_finished.lock() else {
            return Ok(());
        };
        let Ok((_finished, timeout)) =
            self.shutdown_condvar
                .wait_timeout_while(finished, timeout, |f| !*f)
        else {
            return Ok(());
        };
        if timeout.timed_out() {
            return Err(WorkerError::ShutdownTimedOut);
        }
        Ok(())
    }
}
