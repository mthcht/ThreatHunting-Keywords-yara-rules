rule EarthWorm
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string1 = /\/earthworm\.exe/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string2 = "/ew -s lcx_listen -"
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string3 = "/ew -s lcx_slave -"
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string4 = "/ew -s lcx_tran -"
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string5 = "/ew -s rcsocks -"
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string6 = "/ew -s ssocksd -"
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string7 = /\\earthworm\.exe/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string8 = /\\ew\.exe\s\-s\srssocks/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string9 = /\\ew_for_win_32\.exe/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string10 = "32f5aea45557a6aeec3a769c774b105805828aaaa5ceca7b0b3304e0c7f99894" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string11 = "32f5aea45557a6aeec3a769c774b105805828aaaa5ceca7b0b3304e0c7f99894" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string12 = "62b621ead9dd3cc8af73904727d15e469ce06968d274217ac7002fa2f806d8ad" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string13 = "62b621ead9dd3cc8af73904727d15e469ce06968d274217ac7002fa2f806d8ad" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string14 = "95d2ea175a231758503f47fa5c3bcbe647327b9deaae76808b6dda647b574ecd" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string15 = "95d2ea175a231758503f47fa5c3bcbe647327b9deaae76808b6dda647b574ecd" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string16 = "c254dc53b3cf9c7d81d92f4e060a5c44a4f51a228049fd1e2d90fafa9c0a44ee" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string17 = "c254dc53b3cf9c7d81d92f4e060a5c44a4f51a228049fd1e2d90fafa9c0a44ee" nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string18 = /rootkiter\.com\/EarthWorm/ nocase ascii wide
        // Description: SOCKS v5 proxy service used for data forwarding in complex network environments
        // Reference: https://github.com/rootkiter/Binary-files/tree/212c43b40e2e4c2e2703400caaa732557b6080a4
        $string19 = /rootkiter\@sectree\.cn/ nocase ascii wide

    condition:
        any of them
}
