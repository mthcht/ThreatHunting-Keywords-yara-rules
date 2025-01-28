rule PrintNightmare
{
    meta:
        description = "Detection patterns for the tool 'PrintNightmare' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintNightmare"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PrintNightmare exploitation
        // Reference: https://github.com/outflanknl/PrintNightmare
        $string1 = /C\:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\1\\.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}
