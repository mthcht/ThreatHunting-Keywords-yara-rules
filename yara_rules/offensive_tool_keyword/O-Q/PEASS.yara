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
        $string1 = /.{0,1000}\slinpeas\.sh\s.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string2 = /.{0,1000}\s\-linpeas\=http:\/\/127\.0\.0\.1\/linpeas\.sh.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string3 = /.{0,1000}\/linpeas\.sh.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string4 = /.{0,1000}\/PEASS\-ng\.git.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string5 = /.{0,1000}\/PEASS\-ng\/.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string6 = /.{0,1000}\\PEASS\-ng.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string7 = /.{0,1000}gather\/peass\.rb.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string8 = /.{0,1000}linpeas_builder\.py.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string9 = /.{0,1000}linpeas_darwin_amd64.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string10 = /.{0,1000}linpeas_darwin_arm64.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string11 = /.{0,1000}linpeas_fat\.sh.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string12 = /.{0,1000}linpeas_linux_386.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string13 = /.{0,1000}linpeas_linux_amd64.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string14 = /.{0,1000}linpeas_linux_arm64.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string15 = /.{0,1000}metasploit\/peass\.rb.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string16 = /.{0,1000}PEASS\-ng\-master.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string17 = /.{0,1000}winPEAS\.bat.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string18 = /.{0,1000}WinPEAS\.exe.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string19 = /.{0,1000}winPEAS\.ps1.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string20 = /.{0,1000}winPEASany\.exe.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string21 = /.{0,1000}winPEASany_ofs\.exe.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string22 = /.{0,1000}winPEAS\-Obfuscated.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string23 = /.{0,1000}winPEASps1.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string24 = /.{0,1000}winPEASx64\.exe.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string25 = /.{0,1000}winPEASx64_ofs\.exe.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string26 = /.{0,1000}winPEASx86\.exe.{0,1000}/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string27 = /.{0,1000}winPEASx86_ofs\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
