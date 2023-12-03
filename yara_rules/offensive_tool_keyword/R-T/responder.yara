rule responder
{
    meta:
        description = "Detection patterns for the tool 'responder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "responder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string1 = /.{0,1000}\/Analyzer\-Session\.log.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string2 = /.{0,1000}\/FindSQLSrv\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string3 = /.{0,1000}\/NBTNS\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string4 = /.{0,1000}\/poisoners\/.{0,1000}\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string5 = /.{0,1000}\/Responder\.git.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string6 = /.{0,1000}\/responder\/Responder\.conf\s.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string7 = /.{0,1000}\/Responder\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string8 = /.{0,1000}\/tools\/DHCP\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string9 = /.{0,1000}0fa31c8c34a370931d8ffe8097e998f778db63e2e036fbd7727a71a0dcf5d28c.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string10 = /.{0,1000}BrowserListener\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string11 = /.{0,1000}cert.{0,1000}responder\.crt.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string12 = /.{0,1000}cert.{0,1000}responder\.key.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string13 = /.{0,1000}files\/BindShell\.exe.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string14 = /.{0,1000}FindSMB2UPTime\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string15 = /.{0,1000}Icmp\-Redirect\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string16 = /.{0,1000}LLMNR\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string17 = /.{0,1000}Poisoners\-Session\.log.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string18 = /.{0,1000}RelayPackets\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string19 = /.{0,1000}responder\s.{0,1000}\s\-\-lm.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string20 = /.{0,1000}responder\s\-i\s.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string21 = /.{0,1000}Responder\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string22 = /.{0,1000}Responder\-Session\.log.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string23 = /.{0,1000}Responder\-Windows.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string24 = /.{0,1000}SMBRelay\.py.{0,1000}/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string25 = /.{0,1000}SpiderLabs\/Responder.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
