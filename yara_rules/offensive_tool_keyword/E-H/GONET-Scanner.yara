rule GONET_Scanner
{
    meta:
        description = "Detection patterns for the tool 'GONET-Scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GONET-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: port scanner and arp discover in go
        // Reference: https://github.com/luijait/GONET-Scanner
        $string1 = /.{0,1000}\/GONET\-Scanner\/.{0,1000}/ nocase ascii wide
        // Description: port scanner and arp discover in go
        // Reference: https://github.com/luijait/GONET-Scanner
        $string2 = /.{0,1000}\/scannerPort\.go.{0,1000}/ nocase ascii wide
        // Description: port scanner and arp discover in go
        // Reference: https://github.com/luijait/GONET-Scanner
        $string3 = /.{0,1000}go\srun\sscannerPort\.go.{0,1000}/ nocase ascii wide
        // Description: port scanner and arp discover in go
        // Reference: https://github.com/luijait/GONET-Scanner
        $string4 = /.{0,1000}scannerport\.go\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
