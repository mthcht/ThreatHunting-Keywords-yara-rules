rule impersonate_rs
{
    meta:
        description = "Detection patterns for the tool 'impersonate-rs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impersonate-rs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string1 = /.{0,1000}\sexec\s.{0,1000}\s\-p\s.{0,1000}\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string2 = /.{0,1000}\sexec\s.{0,1000}\s\-\-pid\s.{0,1000}\s\-\-command\s.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string3 = /.{0,1000}\/impersonate\-rs.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string4 = /.{0,1000}\/irs\.exe.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string5 = /.{0,1000}\\irs\.exe.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string6 = /.{0,1000}irs\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string7 = /.{0,1000}irs\.exe\sexec.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string8 = /.{0,1000}irs\.exe\slist.{0,1000}/ nocase ascii wide
        // Description: Reimplementation of Defte Impersonate in plain Rust allow you to impersonate any user on the target computer as long as you have administrator privileges (No NT SYSTEM needed) and is usable with and without GUI
        // Reference: https://github.com/zblurx/impersonate-rs
        $string9 = /.{0,1000}irs\.exe\slist.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
