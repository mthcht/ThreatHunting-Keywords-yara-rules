rule QuasarRAT
{
    meta:
        description = "Detection patterns for the tool 'QuasarRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "QuasarRAT"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string1 = /ping\s\-n\s10\slocalhost\s\>\snul/ nocase ascii wide

    condition:
        any of them
}
