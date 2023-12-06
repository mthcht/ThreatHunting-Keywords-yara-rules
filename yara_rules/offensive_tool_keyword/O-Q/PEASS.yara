rule PEASS
{
    meta:
        description = "Detection patterns for the tool 'PEASS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PEASS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string1 = /\slinpeas\.sh\s/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string2 = /\s\-linpeas\=http:\/\/127\.0\.0\.1\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string3 = /\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string4 = /\/PEASS\-ng\.git/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string5 = /\/PEASS\-ng\// nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string6 = /\\PEASS\-ng/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string7 = /gather\/peass\.rb/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string8 = /linpeas_builder\.py/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string9 = /linpeas_darwin_amd64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string10 = /linpeas_darwin_arm64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string11 = /linpeas_fat\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string12 = /linpeas_linux_386/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string13 = /linpeas_linux_amd64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string14 = /linpeas_linux_arm64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string15 = /metasploit\/peass\.rb/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string16 = /PEASS\-ng\-master/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string17 = /winPEAS\.bat/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string18 = /WinPEAS\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string19 = /winPEAS\.ps1/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string20 = /winPEASany\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string21 = /winPEASany_ofs\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string22 = /winPEAS\-Obfuscated/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string23 = /winPEASps1/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string24 = /winPEASx64\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string25 = /winPEASx64_ofs\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string26 = /winPEASx86\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string27 = /winPEASx86_ofs\.exe/ nocase ascii wide

    condition:
        any of them
}
