rule routerpasswords_com
{
    meta:
        description = "Detection patterns for the tool 'routerpasswords.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "routerpasswords.com"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: find default routers passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /routerpasswords\.com\// nocase ascii wide

    condition:
        any of them
}
