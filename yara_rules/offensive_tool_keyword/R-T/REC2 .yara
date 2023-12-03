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
        $string1 = /.{0,1000}\/REC2\.git.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string2 = /.{0,1000}\\REC2\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string3 = /.{0,1000}a78983b009b688a82458abac952516db57dc7eb3118a35cc737dde29c7b87ec4.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string4 = /.{0,1000}c2server_arm_musl.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string5 = /.{0,1000}c2server_armv7.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string6 = /.{0,1000}c2server_debug.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string7 = /.{0,1000}c2server_linux.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string8 = /.{0,1000}c2server_macos.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string9 = /.{0,1000}c2server_release.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string10 = /.{0,1000}c2server_windows.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string11 = /.{0,1000}crate::modules::{rec2mastodon.{0,1000}rec2virustotal}.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string12 = /.{0,1000}d09ccee4\-pass\-word\-0000\-98677e2356fd.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string13 = /.{0,1000}g0h4n\/REC2.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string14 = /.{0,1000}https:\/\/mastodon\.be\/\@username_fzihfzuhfuoz\/109994357971853428.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string15 = /.{0,1000}https:\/\/mastodon\.be\/username_fzihfzuhfuoz\/109743339821428173.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string16 = /.{0,1000}RAMDOMdd28f0dcd9779315ee130deb565dbf315587f1611e54PASSWORD.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string17 = /.{0,1000}REC2\simplant\sfor\sMastodon.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string18 = /.{0,1000}REC2\simplant\sfor\sVirusTotal.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string19 = /.{0,1000}rec2::modules::rec2mastodon.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string20 = /.{0,1000}rec2_mastodon_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string21 = /.{0,1000}rec2_virustotal_x64\.exe.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string22 = /.{0,1000}rec2mastodon\.rs.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string23 = /.{0,1000}rec2virustotal.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string24 = /.{0,1000}rec2virustotal\.rs.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string25 = /.{0,1000}TMVB6XJWzuz4KsqUCnwxrtooQV9LmP6R4IX62HeQ7OZzhxgsahsxNzf05dJNkntl.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string26 = /.{0,1000}Using\sVirusToal\swebsite\sas\sexternal\sC2.{0,1000}/ nocase ascii wide
        // Description: REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust.
        // Reference: https://github.com/g0h4n/REC2
        $string27 = /.{0,1000}WkIKjtCbQzcqQd04ZsE4sFefvpjryhU5w9iVFxGz1oU.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
