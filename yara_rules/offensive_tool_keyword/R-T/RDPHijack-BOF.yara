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
        $string1 = /.{0,1000}beacon_inline_execute.{0,1000}/ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string2 = /.{0,1000}bof\-rdphijack.{0,1000}/ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string3 = /.{0,1000}rdphijack\..{0,1000}/ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string4 = /.{0,1000}rdphijack\.x64\..{0,1000}/ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string5 = /.{0,1000}rdphijack\.x86\..{0,1000}/ nocase ascii wide
        // Description: BOF - RDPHijack - Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking.
        // Reference: https://github.com/netero1010/RDPHijack-BOF
        $string6 = /.{0,1000}RDPHijack\-BOF.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
