// Copyright 2025-Present Datadog, Inc. https://www.datadoghq.com/
// SPDX-License-Identifier: Apache-2.0

#[macro_export]
macro_rules! dd_debug {
    // debug!("a {} event", "log")
    ($($arg:tt)+) => {
      $crate::dd_log!("DEBUG", $($arg)*)
    };
}

#[macro_export]
macro_rules! dd_info {
  // info!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!("INFO", $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_warn {
  // warn!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!("WARN", $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_error {
  // error!("a {} event", "log")
  ($($arg:tt)+) => {
    $crate::dd_log!("ERROR", $($arg)*)
  };
}

#[macro_export]
macro_rules! dd_log {
    ($lvl:expr, $($arg:tt)+) => {
      if $lvl == "ERROR" {
        eprintln!("\x1b[93mERROR\x1b[0m {}:{} - {}", file!(), line!(), format!($($arg)*));
      } else {
        println!("{} {}:{} - {}", $lvl, file!(), line!(), format!($($arg)*));
      }
    };
}
