rule ln
{
    meta:
        description = "Detection patterns for the tool 'ln' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ln"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: covering history tracks on linux system
        // Reference: https://rosesecurity.gitbook.io/red-teaming-ttps/linux
        $string1 = /ln\s\/dev\/null\s\-\/\.bash_history\s\-sf/

    condition:
        any of them
}
