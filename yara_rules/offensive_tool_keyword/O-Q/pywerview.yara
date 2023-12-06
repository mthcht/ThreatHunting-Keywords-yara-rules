rule pywerview
{
    meta:
        description = "Detection patterns for the tool 'pywerview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywerview"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string1 = /\/pywerview/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string2 = /invoke\-checklocaladminaccess/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string3 = /invoke\-eventhunter/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string4 = /invoke\-processhunter/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string5 = /invoke\-userhunter/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string6 = /pywerview\.py/ nocase ascii wide

    condition:
        any of them
}
