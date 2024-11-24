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
        $string4 = " crde_linux https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string5 = " crde_linux_aarch64 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string6 = " crde_linux_x86_64 https -" nocase ascii wide
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
        $string12 = /\shttps\s\-i\s0\.0\.0\.0\s\-P\s.{0,100}\s\-k\s.{0,100}\s\-\-private\-cert\s.{0,100}\s\-\-public\-cert\s/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string13 = " rde1 crde_windows" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string14 = " rde1 srde_linux" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string15 = " rde1 srde_macos" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string16 = " rde1 srde_windows" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string17 = " rec2 crde_linux" nocase ascii wide
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
        $string22 = " srde_linux https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string23 = " srde_linux_aarch64 https -" nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string24 = " srde_linux_x86_64 https -" nocase ascii wide
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
        $string36 = /docker\srun\s.{0,100}\/usr\/src\/rde1/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string37 = /docker\srun\s.{0,100}\/usr\/src\/rec2/ nocase ascii wide
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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
