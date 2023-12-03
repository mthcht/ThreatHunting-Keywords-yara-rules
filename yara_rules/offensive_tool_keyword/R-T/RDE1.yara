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
        $string1 = /.{0,1000}\scrde_arm_musl\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string2 = /.{0,1000}\scrde_armv7\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string3 = /.{0,1000}\scrde_debug\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string4 = /.{0,1000}\scrde_linux\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string5 = /.{0,1000}\scrde_linux_aarch64\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string6 = /.{0,1000}\scrde_linux_x86_64\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string7 = /.{0,1000}\scrde_macos\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string8 = /.{0,1000}\scrde_release\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string9 = /.{0,1000}\scrde_windows\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string10 = /.{0,1000}\scrde_windows_x64\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string11 = /.{0,1000}\scrde_windows_x86\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string12 = /.{0,1000}\shttps\s\-i\s0\.0\.0\.0\s\-P\s.{0,1000}\s\-k\s.{0,1000}\s\-\-private\-cert\s.{0,1000}\s\-\-public\-cert\s.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string13 = /.{0,1000}\srde1\scrde_windows.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string14 = /.{0,1000}\srde1\ssrde_linux.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string15 = /.{0,1000}\srde1\ssrde_macos.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string16 = /.{0,1000}\srde1\ssrde_windows.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string17 = /.{0,1000}\srec2\scrde_linux.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string18 = /.{0,1000}\srec2\scrde_macos.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string19 = /.{0,1000}\ssrde_arm_musl\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string20 = /.{0,1000}\ssrde_armv7\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string21 = /.{0,1000}\ssrde_debug\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string22 = /.{0,1000}\ssrde_linux\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string23 = /.{0,1000}\ssrde_linux_aarch64\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string24 = /.{0,1000}\ssrde_linux_x86_64\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string25 = /.{0,1000}\ssrde_macos\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string26 = /.{0,1000}\ssrde_release\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string27 = /.{0,1000}\ssrde_windows\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string28 = /.{0,1000}\ssrde_windows_x64\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string29 = /.{0,1000}\ssrde_windows_x86\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string30 = /.{0,1000}\/RDE1\.git.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string31 = /.{0,1000}crde\sdns\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string32 = /.{0,1000}crde\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string33 = /.{0,1000}crde::utils::checker.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string34 = /.{0,1000}crde_x64\.exe\sdns\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string35 = /.{0,1000}crde_x64\.exe\shttps\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string36 = /.{0,1000}docker\srun\s.{0,1000}\/usr\/src\/rde1.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string37 = /.{0,1000}docker\srun\s.{0,1000}\/usr\/src\/rec2.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string38 = /.{0,1000}Exfiltration\sfrom\sDNS\sfinished\!.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string39 = /.{0,1000}Exfiltration\sfrom\sHTTPS\sfinished\!.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string40 = /.{0,1000}g0h4n\/RDE1.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string41 = /.{0,1000}methods::dns::dns_exfiltrator.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string42 = /.{0,1000}methods::https::https_exfiltrator.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string43 = /.{0,1000}methods::icmp::icmp_exfiltrator.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string44 = /.{0,1000}RDE1\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string45 = /.{0,1000}srde\sdns\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string46 = /.{0,1000}srde\shttps\s\-.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string47 = /.{0,1000}srde_release\sdns\s\-k\s.{0,1000}/ nocase ascii wide
        // Description: RDE1 (Rusty Data Exfiltrator) is client and server tool allowing auditor to extract files from DNS and HTTPS protocols written in Rust
        // Reference: https://github.com/g0h4n/RDE1
        $string48 = /.{0,1000}srde_release\shttps\s\-i\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
