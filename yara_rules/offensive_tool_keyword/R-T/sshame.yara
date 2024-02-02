rule sshame
{
    meta:
        description = "Detection patterns for the tool 'sshame' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshame"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tool to brute force SSH public-key authentication
        // Reference: https://github.com/HynekPetrak/sshame
        $string1 = /\/sshame/ nocase ascii wide

    condition:
        any of them
}
