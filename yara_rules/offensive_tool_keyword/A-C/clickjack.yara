rule clickjack
{
    meta:
        description = "Detection patterns for the tool 'clickjack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "clickjack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\s\-\-CollectLinks\s\-\-apitoken\s.{0,1000}\s\-\-outfile\s/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\s\-\-Inject\s\-\-stub\s.{0,1000}\.dll.{0,1000}\s\-\-app\s/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\/ClickJack\.exe/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\[\!\]\sThis\sapplication\scan\snot\sbe\sinjected/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\[\+\]\sThis\sapplication\sis\sinjectable\!/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\\ClickJack\.csproj/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\\ClickJack\.exe/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /02FAF312\-BF2A\-466B\-8AD2\-1339A31C303B/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /40e8b756d0f996d7127ffc76d3fb122dd014455bc6b0c007e6d5d77e5bb6211b/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /88f333f2f21ca05e44a91c376022997c2bbec79b9d9982d59ee6d38183df86f3/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /InjectApp\.InfectClickonceApp\(/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /using\sClickJack\.Extensions/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /using\sClickJack\.Modules/ nocase ascii wide

    condition:
        any of them
}
