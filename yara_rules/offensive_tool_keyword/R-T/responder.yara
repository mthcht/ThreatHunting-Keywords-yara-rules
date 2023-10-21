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
        $string1 = /\/Analyzer\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string2 = /\/FindSQLSrv\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string3 = /\/NBTNS\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string4 = /\/poisoners\/.*\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string5 = /\/Responder\.git/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string6 = /\/responder\/Responder\.conf\s/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string7 = /\/Responder\-master\.zip/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string8 = /\/tools\/DHCP\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string9 = /0fa31c8c34a370931d8ffe8097e998f778db63e2e036fbd7727a71a0dcf5d28c/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string10 = /BrowserListener\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string11 = /cert.*responder\.crt/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string12 = /cert.*responder\.key/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string13 = /files\/BindShell\.exe/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string14 = /FindSMB2UPTime\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string15 = /Icmp\-Redirect\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string16 = /LLMNR\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string17 = /Poisoners\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string18 = /RelayPackets\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string19 = /responder\s.*\s\-\-lm/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string20 = /responder\s\-i\s/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string21 = /Responder\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string22 = /Responder\-Session\.log/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string23 = /Responder\-Windows/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string24 = /SMBRelay\.py/ nocase ascii wide
        // Description: LLMNR. NBT-NS and MDNS poisoner
        // Reference: https://github.com/SpiderLabs/Responder
        $string25 = /SpiderLabs\/Responder/ nocase ascii wide

    condition:
        any of them
}