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
        $string1 = /\simport\sLinpeasBaseBuilder/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string2 = /\simport\sLinpeasBuilder/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string3 = /\simport\sPEASLoaded/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string4 = /\simport\sPEASRecord/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string5 = /\slinpeas\.sh\s/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string6 = /\s\-linpeas\=http\:\/\// nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string7 = /\s\-linpeas\=http\:\/\/127\.0\.0\.1\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string8 = /\sWinPEAS\s\-\sWindows\slocal\sPrivilege\sEscalation\sAwesome\sScript/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string9 = /\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string10 = /\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string11 = /\/linpeas\.txt/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string12 = /\/linpeasBaseBuilder\.py/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string13 = /\/linpeasBuilder\.py/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string14 = /\/PEASS\-ng\.git/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string15 = /\/PEASS\-ng\// nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string16 = /\[\+\]\sBuilding\sGTFOBins\slists/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string17 = /\[\+\]\sBuilding\slinux\sexploit\ssuggesters/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string18 = /\[\+\]\sDownloading\sFat\sLinpeas\sbinaries/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string19 = /\\PEASS\-ng/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string20 = /\\winPEAS\.sln/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string21 = /\\winPEASexe\\/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string22 = /66AA4619\-4D0F\-4226\-9D96\-298870E9BB50/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string23 = /builder\/linpeas_parts\// nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string24 = /D934058E\-A7DB\-493F\-A741\-AE8E3DF867F4/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string25 = /gather\/peass\.rb/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string26 = /linpeas_builder\.py/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string27 = /linpeas_darwin_amd64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string28 = /linpeas_darwin_arm64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string29 = /linpeas_fat\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string30 = /linpeas_linux_386/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string31 = /linpeas_linux_amd64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string32 = /linpeas_linux_arm64/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string33 = /metasploit\/peass\.rb/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string34 = /PEASS\-ng\-master/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string35 = /winPEAS\.bat/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string36 = /WinPEAS\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string37 = /winPEAS\.ps1/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string38 = /winPEASany\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string39 = /winPEASany_ofs\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string40 = /winPEAS\-Obfuscated/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string41 = /winPEASps1/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string42 = /winPEASx64\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string43 = /winPEASx64_ofs\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string44 = /winPEASx86\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string45 = /winPEASx86_ofs\.exe/ nocase ascii wide

    condition:
        any of them
}
