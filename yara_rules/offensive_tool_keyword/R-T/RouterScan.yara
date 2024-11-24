rule RouterScan
{
    meta:
        description = "Detection patterns for the tool 'RouterScan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RouterScan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string1 = "/pixiewps --" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string2 = /\/pixiewps\/archive\/master\.zip/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string3 = /\/Routerscan\.7z/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string4 = /\/RouterScan\.exe/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string5 = /\/router\-scan\.git/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string6 = /\/RouterScan\.log/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string7 = /\/wlanpass\.txt/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string8 = /\\Routerscan\.7z/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string9 = /\\RouterScan\.exe/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string10 = /\\RouterScan\.log/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string11 = /\\wlanpass\.txt/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string12 = ">Router Scan by Stas'M<" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string13 = "18229920a45130f00539405fecab500d8010ef93856e1c5bcabf5aa5532b3311" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string14 = "49966f985d0d509cebebda87d56da72e6a94253adfb3252000dfff73fb207ff0" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string15 = "b875051a6d584b37810ea48923af45e20d1367adfa94266bfe47a1a35d76b03a" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string16 = "b91166d5623d4077003ae8527e9169092994f5c189c8a3820b32e204b4230578" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string17 = "e97da4284459149541ef261a6de0bec7ef8a3d2d28d3384b7b256c089d524690" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string18 = "f61ebc6c8692c620a57b7b167206e74131df5e4d651ae55713392bde4b0e8b9f" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string19 = /http\:\/\/0x0\.st\/tm/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string20 = /http\:\/\/3wifi\.stascorp\.com\/3wifi\.php/ nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string21 = "mustafashykh/router-scan" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string22 = "pixiewps -e" nocase ascii wide
        // Description: a penetration testing tool to maliciously scan for and brute force routers - cameras and network-attached storage devices with web interfaces
        // Reference: https://github.com/mustafashykh/router-scan
        $string23 = /Upload\.Password\=antichat/ nocase ascii wide

    condition:
        any of them
}
