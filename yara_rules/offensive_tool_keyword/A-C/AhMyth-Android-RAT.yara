rule AhMyth_Android_RAT
{
    meta:
        description = "Detection patterns for the tool 'AhMyth-Android-RAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AhMyth-Android-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AhMyth Android Rat
        // Reference: https://github.com/AhMyth/AhMyth-Android-RAT
        $string1 = /AhMyth\-Android\-RAT/ nocase ascii wide

    condition:
        any of them
}
