rule htran
{
    meta:
        description = "Detection patterns for the tool 'htran' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "htran"
        rule_category = "signature_keyword"

    strings:
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string1 = /Hacktool\.HTran\./ nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string2 = "HackTool:Win32/Htran" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string3 = "HKTL_HTRAN" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string4 = "Riskware/Htran" nocase ascii wide
        // Description: proxies connections through intermediate hops and aids users in disguising their true geographical location. It can be used by adversaries to hide their location when interacting with the victim networks
        // Reference: https://github.com/HiwinCN/Htran
        $string5 = /Win32\/HackTool\.Hucline\.F/ nocase ascii wide

    condition:
        any of them
}
