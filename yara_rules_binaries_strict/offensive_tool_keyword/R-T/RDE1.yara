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
        $string1 = /\scrde_arm_musl\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string2 = /\scrde_armv7\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string3 = /\scrde_debug\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string4 = /\scrde_linux\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string5 = /\scrde_linux_aarch64\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string6 = /\scrde_linux_x86_64\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string7 = /\scrde_macos\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string8 = /\scrde_release\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string9 = /\scrde_windows\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string10 = /\scrde_windows_x64\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string11 = /\scrde_windows_x86\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string12 = /\shttps\s\-i\s0\.0\.0\.0\s\-P\s.{0,100}\s\-k\s.{0,100}\s\-\-private\-cert\s.{0,100}\s\-\-public\-cert\s/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string13 = /\srde1\scrde_windows/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string14 = /\srde1\ssrde_linux/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string15 = /\srde1\ssrde_macos/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string16 = /\srde1\ssrde_windows/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string17 = /\srec2\scrde_linux/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string18 = /\srec2\scrde_macos/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string19 = /\ssrde_arm_musl\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string20 = /\ssrde_armv7\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string21 = /\ssrde_debug\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string22 = /\ssrde_linux\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string23 = /\ssrde_linux_aarch64\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string24 = /\ssrde_linux_x86_64\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string25 = /\ssrde_macos\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string26 = /\ssrde_release\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string27 = /\ssrde_windows\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string28 = /\ssrde_windows_x64\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string29 = /\ssrde_windows_x86\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string30 = /\/RDE1\.git/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string31 = /crde\sdns\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string32 = /crde\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string33 = /crde\:\:utils\:\:checker/ nocase ascii wide
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
        $string38 = /Exfiltration\sfrom\sDNS\sfinished\!/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string39 = /Exfiltration\sfrom\sHTTPS\sfinished\!/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string40 = /g0h4n\/RDE1/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string41 = /methods\:\:dns\:\:dns_exfiltrator/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string42 = /methods\:\:https\:\:https_exfiltrator/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string43 = /methods\:\:icmp\:\:icmp_exfiltrator/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string44 = /RDE1\-main\.zip/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string45 = /srde\sdns\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string46 = /srde\shttps\s\-/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string47 = /srde_release\sdns\s\-k\s/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string48 = /srde_release\shttps\s\-i\s/ nocase ascii wide
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
