rule dir
{
    meta:
        description = "Detection patterns for the tool 'dir' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dir"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: threat actors searched for Active Directory related DLLs in directories
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string1 = /\sdir\s\/s\s.{0,1000}\/\sMicrosoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide
        // Description: lists files and directories in the c:\windows\kb directory related to updates or system configurations
        // Reference: N/A
        $string2 = /dir\s\/a\s\/b\sc\:\\windows\\kb/ nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string3 = /dir\s\/a\:h\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string4 = /dir\s\/a\:h\sC\:\\Users\\.{0,1000}\\AppData\\Roaming\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: List Users with dir
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string5 = /dir\s\/b\s\/ad\s\"C\:\\Users\"/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string6 = /dir\s\/b\/a\s\%appdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
        // Description: associated with PEASS-ng - Privilege Escalation Awesome Scripts suite
        // Reference: https://github.com/peass-ng/PEASS-ng
        $string7 = /dir\s\/b\/a\s\%localappdata\%\\Microsoft\\Credentials\\\s2\>nul/ nocase ascii wide
        // Description: Find the IDs of protected secrets for a specific user
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string8 = /dir\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials/ nocase ascii wide

    condition:
        any of them
}
