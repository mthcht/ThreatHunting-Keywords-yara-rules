rule EarthWorm
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "signature_keyword"

    strings:
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string1 = /ELF\:Earthworm\-B/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string2 = /HackTool\.EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string3 = /Hacktool\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string4 = /HackTool\.Linux\.EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string5 = /HackTool\.Win32\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string6 = /HackTool\/Win32\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string7 = /HackTool\:Linux\/EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string8 = /Linux\.Hacktool\.Earthworm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string9 = /Tool\.Linux\.EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string10 = /Win\.Tool\.Earthworm\-/ nocase ascii wide

    condition:
        any of them
}
