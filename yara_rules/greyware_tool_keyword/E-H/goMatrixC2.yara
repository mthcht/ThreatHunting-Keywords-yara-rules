rule goMatrixC2
{
    meta:
        description = "Detection patterns for the tool 'goMatrixC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goMatrixC2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string1 = /https\:\/\/matrix\.org\/_matrix\/client\/r0\/rooms\/.{0,1000}\/send\/m\.room\.message/ nocase ascii wide

    condition:
        any of them
}
