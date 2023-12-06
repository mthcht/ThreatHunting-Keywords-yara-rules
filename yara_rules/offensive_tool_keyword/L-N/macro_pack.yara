rule macro_pack
{
    meta:
        description = "Detection patterns for the tool 'macro_pack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macro_pack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string1 = /macro_pack/ nocase ascii wide

    condition:
        any of them
}
