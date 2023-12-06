rule Operative_Framework
{
    meta:
        description = "Detection patterns for the tool 'Operative Framework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Operative Framework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Framework based on fingerprint action. this tool is used for get information on a website or a enterprise target with multiple modules.
        // Reference: https://github.com/graniet/operative-framework
        $string1 = /Operative\sFramework/ nocase ascii wide

    condition:
        any of them
}
