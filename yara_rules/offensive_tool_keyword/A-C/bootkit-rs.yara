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
        $string1 = /\/bootkit\-rs/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string2 = /\\bootkit\-rs/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string3 = /bootkit\-rs\.git/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string4 = /bootkit\-rs\-master/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string5 = /master\/bootkit\/src/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string6 = /redlotus\.efi/ nocase ascii wide
        // Description: Rusty Bootkit - Windows UEFI Bootkit in Rust (Codename: RedLotus)
        // Reference: https://github.com/memN0ps/bootkit-rs
        $string7 = /x86_64\-unknown\-uefi/ nocase ascii wide

    condition:
        any of them
}
