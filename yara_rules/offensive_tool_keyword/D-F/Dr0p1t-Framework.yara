rule Dr0p1t_Framework
{
    meta:
        description = "Detection patterns for the tool 'Dr0p1t-Framework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dr0p1t-Framework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Have you ever heard about trojan droppers ? In short dropper is type of malware that downloads other malwares and Dr0p1t gives you the chance to create a stealthy dropper that bypass most AVs and have a lot of tricks ( Trust me :D ) .)
        // Reference: https://github.com/D4Vinci/Dr0p1t-Framework
        $string1 = /Dr0p1t\-Framework/ nocase ascii wide

    condition:
        any of them
}
