// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[macro_export]
macro_rules! debug {
    // debug!("a {} event", "log")
    ($($arg:tt)+) => {
      $crate::log!("DEBUG", $($arg)*)
    };
}

#[macro_export]
macro_rules! info {
  // info!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::log!("INFO", $($arg)*)
  };
}

#[macro_export]
macro_rules! warn {
  // warn!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::log!("WARN", $($arg)*)
  };
}

#[macro_export]
macro_rules! error {
  // error!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::log!("ERROR", $($arg)*)
  };
}

#[macro_export]
macro_rules! log {
    ($lvl:expr, $($arg:tt)+) => {
      if $lvl == "ERROR" {
        eprintln!("\x1b[93mERROR\x1b[0m {}:{} - {}", file!(), line!(), format!($($arg)*));
      } else {
        println!("{} {}:{} - {}", $lvl, file!(), line!(), format!($($arg)*));
      }
    };
}
