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
        $string1 = /.{0,1000}\/DeNiSe\.git.{0,1000}/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string2 = /.{0,1000}DeNiSe\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string3 = /.{0,1000}DeNiSePkg\.py.{0,1000}/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string4 = /.{0,1000}dnslog\-\-airvent\.txt.{0,1000}/ nocase ascii wide
        // Description: DeNiSe is a proof of concept for tunneling TCP over DNS in Python
        // Reference: https://github.com/mdornseif/DeNiSe
        $string5 = /.{0,1000}mdornseif\/DeNiSe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
