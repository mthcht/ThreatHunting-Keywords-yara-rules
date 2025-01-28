rule REC2_
{
    meta:
        description = "Detection patterns for the tool 'REC2 ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "REC2 "
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string1 = /\/REC2\.git/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string2 = /\\REC2\-main\.zip/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string3 = "a78983b009b688a82458abac952516db57dc7eb3118a35cc737dde29c7b87ec4" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string4 = "c2server_arm_musl" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string5 = "c2server_armv7" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string6 = "c2server_debug" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string7 = "c2server_linux"
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string8 = "c2server_macos" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string9 = "c2server_release" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string10 = "c2server_windows" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string11 = /crate\:\:modules\:\:\{rec2mastodon.{0,100}rec2virustotal\}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string12 = "d09ccee4-pass-word-0000-98677e2356fd" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string13 = "g0h4n/REC2" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string14 = /https\:\/\/mastodon\.be\/\@username_fzihfzuhfuoz\/109994357971853428/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string15 = /https\:\/\/mastodon\.be\/username_fzihfzuhfuoz\/109743339821428173/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string16 = "RAMDOMdd28f0dcd9779315ee130deb565dbf315587f1611e54PASSWORD" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string17 = "REC2 implant for Mastodon" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string18 = "REC2 implant for VirusTotal" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string19 = "rec2::modules::rec2mastodon" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string20 = /rec2_mastodon_x64\.exe/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string21 = /rec2_virustotal_x64\.exe/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string22 = /rec2mastodon\.rs/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string23 = "rec2virustotal" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string24 = /rec2virustotal\.rs/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string25 = "TMVB6XJWzuz4KsqUCnwxrtooQV9LmP6R4IX62HeQ7OZzhxgsahsxNzf05dJNkntl" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string26 = "Using VirusToal website as external C2" nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string27 = "WkIKjtCbQzcqQd04ZsE4sFefvpjryhU5w9iVFxGz1oU" nocase ascii wide
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
