rule DirtyCLR
{
    meta:
        description = "Detection patterns for the tool 'DirtyCLR' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DirtyCLR"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string1 = /\/DirtyCLR\.git/ nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string2 = /\\DirtyCLR\.sln/ nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string3 = /\\DirtyCLR\-main/ nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string4 = ">DirtyCLR<" nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string5 = "46EB7B83-3404-4DFC-94CC-704B02D11464" nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string6 = "827310760fa3d7371a22ff5f06e406f3e0a6cbe1c7e7f38244e0334a2d5eca7d" nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string7 = "8e2f8144fae305ecff5759bb38e384682642e766dfe85179555d7b621d92b836" nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string8 = "dirtyclrdomain" nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string9 = "ipSlav/DirtyCLR" nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string10 = /key.{0,1000}kda47y298uned/ nocase ascii wide
        // Description: An App Domain Manager Injection DLL PoC
        // Reference: https://github.com/ipSlav/DirtyCLR
        $string11 = /sn\.exe\s\-k\skey\.snk/ nocase ascii wide

    condition:
        any of them
}
