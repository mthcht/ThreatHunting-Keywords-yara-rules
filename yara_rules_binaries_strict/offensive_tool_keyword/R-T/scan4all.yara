rule scan4all
{
    meta:
        description = "Detection patterns for the tool 'scan4all' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scan4all"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string1 = /\s\-l\snmapRssuilt\.xml\s\-v/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string2 = /\.\/scan4all\s/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string3 = /\.\/scan4all/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string4 = /\/config\/doNmapScanWin\.bat\s/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string5 = /\/CVE\-.{0,100}\-.{0,100}_POC\.py/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string6 = /\/CVE\-2022\-.{0,100}\.go/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string7 = /\/dicts\/ftp_default\.txt/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string8 = /\/scan4all\.exe/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string9 = /\/scan4all\.git/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string10 = /\/scan4all\.git/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string11 = /\/scan4all\.rb/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string12 = /\/scan4all\/lib\/api/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string13 = /\/scan4all\/lib\/util/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string14 = /\\scan4all\.exe/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string15 = /\\scan4all\-main/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string16 = /async_webshell\-all\.py/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string17 = /config\/51pwn\/CVE\-/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string18 = /dicts\/ftp_pswd\.txt/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string19 = /dicts\/ssh_default\.txt/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string20 = /dicts\/ssh_pswd\.txt/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string21 = /hktalent\/scan4all/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string22 = /hktalent\/scan4all/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string23 = /pocs_go\/.{0,100}\/CVE\-.{0,100}\.go/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string24 = /scan4all\s\-/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string25 = /scan4all\s\-.{0,100}\.xml/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string26 = /scan4all\s\-h/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string27 = /scan4all\s\-tp\s/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string28 = /scan4all\.51pwn\.com/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string29 = /scan4all\.51pwn\.com\// nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string30 = /scan4all_.{0,100}\..{0,100}_linux_amd64\.zip/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string31 = /scan4all_.{0,100}\..{0,100}_macOS_amd64\.zip/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string32 = /scan4all_.{0,100}\..{0,100}_macOS_arm64\.zip/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string33 = /scan4all_.{0,100}\..{0,100}_windows_amd64\.zip/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string34 = /scan4all_.{0,100}_linux_amd64\.zip/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string35 = /scan4all_.{0,100}_windows_amd64\.zip/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string36 = /scan4all_windows_386\.exe/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string37 = /scan4all_windows_amd64\.exe/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string38 = /scan4all\-main/ nocase ascii wide
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
