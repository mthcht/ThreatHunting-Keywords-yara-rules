rule RDPHijack_BOF
{
    meta:
        description = "Detection patterns for the tool 'RDPHijack-BOF' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPHijack-BOF"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string1 = /beacon_inline_execute/ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string2 = /bof\-rdphijack/ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string3 = /rdphijack\./ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string4 = /rdphijack\.x64\./ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string5 = /rdphijack\.x86\./ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string6 = /RDPHijack\-BOF/ nocase ascii wide

    condition:
        any of them
}
