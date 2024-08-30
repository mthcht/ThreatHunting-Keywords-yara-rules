rule GhostDriver
{
    meta:
        description = "Detection patterns for the tool 'GhostDriver' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostDriver"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string1 = /\sGhostDriver\.exe/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string2 = /\sghostdriver\.sys/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string3 = /\/GhostDriver\.exe/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string4 = /\/GhostDriver\.git/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string5 = /\/ghostdriver\.sys/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string6 = /\[\!\]\scleaning\sup\sall\sIOCs\sfiles\sto\savoid\sdetection\!/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string7 = /\\GhostDriver\.exe/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string8 = /\\ghostdriver\.sys/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string9 = /\\GhostDriver\-main\\/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string10 = /\\rentdrv\.log/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string11 = /BlackSnufkin\/GhostDriver/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string12 = /GhostDriver\.exe\s/ nocase ascii wide
        // Description: GhostDriver is a Rust-built AV killer tool using BYOVD
        // Reference: https://github.com/BlackSnufkin/GhostDriver
        $string13 = /GhostDriver\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
