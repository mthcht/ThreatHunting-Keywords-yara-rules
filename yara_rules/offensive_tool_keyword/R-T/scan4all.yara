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
        $string1 = /.{0,1000}\s\-l\snmapRssuilt\.xml\s\-v.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string2 = /.{0,1000}\.\/scan4all\s.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string3 = /.{0,1000}\.\/scan4all.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string4 = /.{0,1000}\/config\/doNmapScanWin\.bat\s.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string5 = /.{0,1000}\/CVE\-.{0,1000}\-.{0,1000}_POC\.py.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string6 = /.{0,1000}\/CVE\-2022\-.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string7 = /.{0,1000}\/dicts\/ftp_default\.txt.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string8 = /.{0,1000}\/scan4all\.exe.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string9 = /.{0,1000}\/scan4all\.git.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string10 = /.{0,1000}\/scan4all\.git.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string11 = /.{0,1000}\/scan4all\.rb.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string12 = /.{0,1000}\/scan4all\/lib\/api.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string13 = /.{0,1000}\/scan4all\/lib\/util.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string14 = /.{0,1000}\\scan4all\.exe.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string15 = /.{0,1000}\\scan4all\-main.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string16 = /.{0,1000}async_webshell\-all\.py.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string17 = /.{0,1000}config\/51pwn\/CVE\-.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string18 = /.{0,1000}dicts\/ftp_pswd\.txt.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string19 = /.{0,1000}dicts\/ssh_default\.txt.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string20 = /.{0,1000}dicts\/ssh_pswd\.txt.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string21 = /.{0,1000}hktalent\/scan4all.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string22 = /.{0,1000}hktalent\/scan4all.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string23 = /.{0,1000}pocs_go\/.{0,1000}\/CVE\-.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string24 = /.{0,1000}scan4all\s\-.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string25 = /.{0,1000}scan4all\s\-.{0,1000}\.xml.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string26 = /.{0,1000}scan4all\s\-h.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string27 = /.{0,1000}scan4all\s\-tp\s.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string28 = /.{0,1000}scan4all\.51pwn\.com.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string29 = /.{0,1000}scan4all\.51pwn\.com\/.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string30 = /.{0,1000}scan4all_.{0,1000}\..{0,1000}_linux_amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string31 = /.{0,1000}scan4all_.{0,1000}\..{0,1000}_macOS_amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string32 = /.{0,1000}scan4all_.{0,1000}\..{0,1000}_macOS_arm64\.zip.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string33 = /.{0,1000}scan4all_.{0,1000}\..{0,1000}_windows_amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string34 = /.{0,1000}scan4all_.{0,1000}_linux_amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoC
        // Reference: https://github.com/hktalent/scan4all
        $string35 = /.{0,1000}scan4all_.{0,1000}_windows_amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string36 = /.{0,1000}scan4all_windows_386\.exe.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string37 = /.{0,1000}scan4all_windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: Official repository vuls Scan: 15000+PoCs - 23 kinds of application password crack - 7000+Web fingerprints - 146 protocols and 90000+ rules Port scanning - Fuzz - HW - awesome BugBounty
        // Reference: https://github.com/hktalent/scan4all
        $string38 = /.{0,1000}scan4all\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
