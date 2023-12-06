rule Freeze_rs
{
    meta:
        description = "Detection patterns for the tool 'Freeze.rs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Freeze.rs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Freeze.rs is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls written in RUST
        // Reference: https://github.com/optiv/Freeze.rs
        $string1 = /\sFreeze\.rs\// nocase ascii wide
        // Description: Freeze.rs is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls written in RUST
        // Reference: https://github.com/optiv/Freeze.rs
        $string2 = /\/Freeze\.rs/ nocase ascii wide
        // Description: Freeze.rs is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls written in RUST
        // Reference: https://github.com/optiv/Freeze.rs
        $string3 = /Freeze\-rs\s\-/ nocase ascii wide
        // Description: Freeze.rs is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls written in RUST
        // Reference: https://github.com/optiv/Freeze.rs
        $string4 = /Freeze\-rs\.exe/ nocase ascii wide
        // Description: Freeze.rs is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls written in RUST
        // Reference: https://github.com/optiv/Freeze.rs
        $string5 = /Freeze\-rs_darwin_amd64/ nocase ascii wide
        // Description: Freeze.rs is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls written in RUST
        // Reference: https://github.com/optiv/Freeze.rs
        $string6 = /Freeze\-rs_linux_amd64/ nocase ascii wide
        // Description: Freeze.rs is a payload toolkit for bypassing EDRs using suspended processes. direct syscalls written in RUST
        // Reference: https://github.com/optiv/Freeze.rs
        $string7 = /Freeze\-rs_windows_amd64\.exe/ nocase ascii wide

    condition:
        any of them
}
