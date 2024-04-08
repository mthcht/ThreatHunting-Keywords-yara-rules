rule takeown
{
    meta:
        description = "Detection patterns for the tool 'takeown' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "takeown"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1 = /takeown\s\/f\s\"C\:\\windows\\system32\\config\\SAM\"/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string2 = /takeown\s\/f\sC\:\\Windows\\System32\\amsi\.dll\s\/a/ nocase ascii wide
        // Description: automated sticky keys backdoor + credentials harvesting
        // Reference: https://github.com/l3m0n/WinPirate
        $string3 = /takeown\s\/f\sc\:\\windows\\system32\\sethc\.exe/ nocase ascii wide
        // Description: automated sticky keys backdoor + credentials harvesting
        // Reference: https://github.com/l3m0n/WinPirate
        $string4 = /takeown\s\/f\sc\:\\windows\\system32\\sethcold\.exe/ nocase ascii wide

    condition:
        any of them
}
