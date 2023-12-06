rule al_khaser
{
    meta:
        description = "Detection patterns for the tool 'al-khaser' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "al-khaser"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: al-khaser is a PoC malware application with good intentions that aims to stress your anti-malware system. It performs a bunch of common malware tricks with the goal of seeing if you stay under the radar
        // Reference: https://github.com/LordNoteworthy/al-khaser
        $string1 = /al\-khaser/ nocase ascii wide

    condition:
        any of them
}
