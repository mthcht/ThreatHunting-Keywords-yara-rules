rule APT
{
    meta:
        description = "Detection patterns for the tool 'APT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "APT"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - backdoor apt execute a command when invoking apt
        // Reference: N/A
        $string1 = /APT::Update::Pre\-Invoke\s.*}/ nocase ascii wide

    condition:
        any of them
}