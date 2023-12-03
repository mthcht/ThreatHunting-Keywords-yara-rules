rule bootkit_rs
{
    meta:
        description = "Detection patterns for the tool 'bootkit-rs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bootkit-rs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string1 = /.{0,1000}\/bootkit\-rs.{0,1000}/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string2 = /.{0,1000}\\bootkit\-rs.{0,1000}/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string3 = /.{0,1000}bootkit\-rs\.git.{0,1000}/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string4 = /.{0,1000}bootkit\-rs\-master.{0,1000}/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string5 = /.{0,1000}master\/bootkit\/src.{0,1000}/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string6 = /.{0,1000}redlotus\.efi.{0,1000}/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string7 = /.{0,1000}x86_64\-unknown\-uefi.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
