rule copy
{
    meta:
        description = "Detection patterns for the tool 'copy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "copy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: copying an executable to a remote machine in the c:\windows directory
        // Reference: https://x.com/ACEResponder/status/1720906842631549377
        $string1 = /copy\s.*\.exe\s\\\\.*\\c\$\\Windows\\.*\.exe/ nocase ascii wide
        // Description: the actor creating a Shadow Copy and then extracting a copy of the ntds.dit file from it.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string2 = /copy\s.*\\NTDS\\ntds\.dit\s.*\\Temp\\.*\./ nocase ascii wide
        // Description: copy the NTDS.dit file from a Volume Shadow Copy which contains sensitive Active Directory data including password hashes for all domain users
        // Reference: N/A
        $string3 = /copy\s.*NTDS\\NTDS\.dit.*Temp/ nocase ascii wide

    condition:
        any of them
}