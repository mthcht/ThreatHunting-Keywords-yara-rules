rule SnaffPoint
{
    meta:
        description = "Detection patterns for the tool 'SnaffPoint' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SnaffPoint"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for pointesters to find candies in SharePoint
        // Reference: https://github.com/nheiniger/SnaffPoint
        $string1 = /\/SnaffPoint\.git/ nocase ascii wide
        // Description: A tool for pointesters to find candies in SharePoint
        // Reference: https://github.com/nheiniger/SnaffPoint
        $string2 = /879A49C7\-0493\-4235\-85F6\-EBF962613A76/ nocase ascii wide
        // Description: A tool for pointesters to find candies in SharePoint
        // Reference: https://github.com/nheiniger/SnaffPoint
        $string3 = /GetBearerToken\.exe\shttps\:\/\/.{0,1000}\.sharepoint\.com/ nocase ascii wide
        // Description: A tool for pointesters to find candies in SharePoint
        // Reference: https://github.com/nheiniger/SnaffPoint
        $string4 = /nheiniger\/SnaffPoint/ nocase ascii wide
        // Description: A tool for pointesters to find candies in SharePoint
        // Reference: https://github.com/nheiniger/SnaffPoint
        $string5 = /SnaffPoint\.exe/ nocase ascii wide
        // Description: A tool for pointesters to find candies in SharePoint
        // Reference: https://github.com/nheiniger/SnaffPoint
        $string6 = /SnaffPoint\-main/ nocase ascii wide

    condition:
        any of them
}
