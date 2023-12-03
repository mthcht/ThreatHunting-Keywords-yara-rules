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
        $string1 = /.{0,1000}\/pywerview.{0,1000}/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string2 = /.{0,1000}invoke\-checklocaladminaccess.{0,1000}/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string3 = /.{0,1000}invoke\-eventhunter.{0,1000}/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string4 = /.{0,1000}invoke\-processhunter.{0,1000}/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string5 = /.{0,1000}invoke\-userhunter.{0,1000}/ nocase ascii wide
        // Description: A partial Python rewriting of PowerSploit PowerView
        // Reference: https://github.com/the-useless-one/pywerview
        $string6 = /.{0,1000}pywerview\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
