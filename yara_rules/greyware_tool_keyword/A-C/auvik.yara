rule auvik
{
    meta:
        description = "Detection patterns for the tool 'auvik' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "auvik"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: cloud-based network management software
        // Reference: https://www.auvik.com/
        $string1 = /\>Auvik\sNetworks\sInc\.\</ nocase ascii wide
        // Description: cloud-based network management software
        // Reference: https://www.auvik.com/
        $string2 = /auvik\.agent\.exe/ nocase ascii wide
        // Description: cloud-based network management software
        // Reference: https://www.auvik.com/
        $string3 = /AuvikService\.exe/ nocase ascii wide
        // Description: cloud-based network management software
        // Reference: https://www.auvik.com/
        $string4 = /https\:\/\/.{0,1000}\.my\.auvik\.com\// nocase ascii wide

    condition:
        any of them
}
