rule FudgeC2
{
    meta:
        description = "Detection patterns for the tool 'FudgeC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FudgeC2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string1 = /http.{0,1000}\/\/127\.0\.0\.1\:5001/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string2 = /http.{0,1000}\/\/localhost\:5001/ nocase ascii wide

    condition:
        any of them
}
