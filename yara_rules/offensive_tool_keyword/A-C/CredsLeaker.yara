rule CredsLeaker
{
    meta:
        description = "Detection patterns for the tool 'CredsLeaker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CredsLeaker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script used to display a powershell credentials box asked the user for credentials. However. That was highly noticeable. Now its time to utilize Windows Security popup!
        // Reference: https://github.com/Dviros/CredsLeaker
        $string1 = /CredsLeaker/ nocase ascii wide

    condition:
        any of them
}
