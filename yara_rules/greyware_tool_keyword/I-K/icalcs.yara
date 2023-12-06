rule icalcs
{
    meta:
        description = "Detection patterns for the tool 'icalcs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icalcs"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1 = /icacls\s\"C:\\windows\\system32\\config\\SAM\"\s\/grant/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string2 = /icacls\.exe\sC:\\Windows\\System32\\amsi\.dll\s\/grant\sadministrators:F/ nocase ascii wide

    condition:
        any of them
}
