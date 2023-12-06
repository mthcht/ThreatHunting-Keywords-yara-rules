rule InsecurePowerShell
{
    meta:
        description = "Detection patterns for the tool 'InsecurePowerShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InsecurePowerShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: powershell without securities features
        // Reference: https://github.com/cobbr/InsecurePowerShell
        $string1 = /InsecurePowerShell/ nocase ascii wide

    condition:
        any of them
}
