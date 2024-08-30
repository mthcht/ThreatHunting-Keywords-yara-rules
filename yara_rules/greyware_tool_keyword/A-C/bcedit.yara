rule bcedit
{
    meta:
        description = "Detection patterns for the tool 'bcedit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bcedit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: This checks whether the script has administrative access before continuing
        // Reference: https://github.com/Lifka/hacking-resources/blob/7885f95676c3ba4b2ee79fbaf0f6797add892322/system-hacking-cheat-sheet.md?plain=1#L114
        $string1 = /FOR\s\/F\s\"tokens\=1\,2.{0,1000}\"\s\%\%V\sIN\s\(\'bcdedit\'\)\sDO\sSET\sadminTest\=\%\%V/ nocase ascii wide

    condition:
        any of them
}
