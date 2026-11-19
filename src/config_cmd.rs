//! thorn config show / set: the settings the web UI's Settings page changes.

use crate::{ops, sys, units};
use anyhow::Result;

pub fn show() -> Result<()> {
    for s in ops::config_show()? {
        let value = if s.value.is_empty() {
            "(empty)"
        } else {
            &s.value
        };
        println!("{} = {value}\n    {}\n", s.key, s.help);
    }
    Ok(())
}

pub fn set(key: &str, value: &str) -> Result<()> {
    let r = ops::config_set(
        &[(key.to_string(), value.to_string())],
        ops::ssh_client(),
        false,
    )?;
    println!("changed {} and applied it", r.changed.join(", "));
    if let Some(urls) = r.web_moved {
        sys::systemctl(&["try-restart", units::WEB])?;
        println!("the web UI is now on {}", urls.join(" "));
    }
    Ok(())
}
