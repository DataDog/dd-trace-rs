// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

pub type Result<T> = std::result::Result<T, Error>;

#[repr(transparent)]
pub struct Error {
    inner: anyhow::Error,
}

impl<E> From<E> for Error
where
    E: std::error::Error + Sync + Send + 'static,
{
    fn from(error: E) -> Self {
        Self {
            inner: anyhow::Error::new(error),
        }
    }
}

impl From<Error> for Box<dyn std::error::Error + Send + Sync> {
    fn from(error: Error) -> Box<dyn std::error::Error + Send + Sync> {
        error.inner.into()
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}
