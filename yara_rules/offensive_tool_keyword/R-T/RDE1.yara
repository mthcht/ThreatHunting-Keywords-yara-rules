rule RDE1
{
    meta:
        description = "Detection patterns for the tool 'RDE1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDE1"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string1 = " crde_arm_musl https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string2 = " crde_armv7 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string3 = " crde_debug https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string4 = " crde_linux https -"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string5 = " crde_linux_aarch64 https -"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string6 = " crde_linux_x86_64 https -"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string7 = " crde_macos https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string8 = " crde_release https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string9 = " crde_windows https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string10 = " crde_windows_x64 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string11 = " crde_windows_x86 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string12 = /\shttps\s\-i\s0\.0\.0\.0\s\-P\s.{0,1000}\s\-k\s.{0,1000}\s\-\-private\-cert\s.{0,1000}\s\-\-public\-cert\s/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string13 = " rde1 crde_windows" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string14 = " rde1 srde_linux"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string15 = " rde1 srde_macos" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string16 = " rde1 srde_windows" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string17 = " rec2 crde_linux"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string18 = " rec2 crde_macos" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string19 = " srde_arm_musl https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string20 = " srde_armv7 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string21 = " srde_debug https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string22 = " srde_linux https -"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string23 = " srde_linux_aarch64 https -"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string24 = " srde_linux_x86_64 https -"
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string25 = " srde_macos https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string26 = " srde_release https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string27 = " srde_windows https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string28 = " srde_windows_x64 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string29 = " srde_windows_x86 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string30 = /\/RDE1\.git/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string31 = "crde dns -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string32 = "crde https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string33 = "crde::utils::checker" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string34 = /crde_x64\.exe\sdns\s\-f\s/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string35 = /crde_x64\.exe\shttps\s\-f\s/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string36 = /docker\srun\s.{0,1000}\/usr\/src\/rde1/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string37 = /docker\srun\s.{0,1000}\/usr\/src\/rec2/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string38 = "Exfiltration from DNS finished!" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string39 = "Exfiltration from HTTPS finished!" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string40 = "g0h4n/RDE1" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string41 = "methods::dns::dns_exfiltrator" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string42 = "methods::https::https_exfiltrator" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string43 = "methods::icmp::icmp_exfiltrator" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string44 = /RDE1\-main\.zip/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string45 = "srde dns -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string46 = "srde https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string47 = "srde_release dns -k " nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string48 = "srde_release https -i " nocase ascii wide

    condition:
        any of them
}
