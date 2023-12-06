rule DeNiSe
{
    meta:
        description = "Detection patterns for the tool 'DeNiSe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeNiSe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string1 = /\/DeNiSe\.git/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string2 = /DeNiSe\-master\.zip/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string3 = /DeNiSePkg\.py/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string4 = /dnslog\-\-airvent\.txt/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string5 = /mdornseif\/DeNiSe/ nocase ascii wide

    condition:
        any of them
}
