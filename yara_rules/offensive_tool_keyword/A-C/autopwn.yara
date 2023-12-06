rule autopwn
{
    meta:
        description = "Detection patterns for the tool 'autopwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autopwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: tools for pentester. autopwn is designed to make a pentesters life easier and more consistent by allowing them to specify tools they would like to run against targets. without having to type them in a shell or write a script. This tool will probably be useful during certain exams as well..
        // Reference: https://github.com/nccgroup/autopwn
        $string1 = /autopwn/ nocase ascii wide

    condition:
        any of them
}
