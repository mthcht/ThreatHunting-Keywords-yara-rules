rule ligolo_ng
{
    meta:
        description = "Detection patterns for the tool 'ligolo-ng' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ligolo-ng"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string1 = /\/agent\s\-connect\shttp.{0,1000}\s\-\-proxy/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string2 = /\/ligolo\-ng\.git/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string3 = /\/ligolo\-ng\/releases/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string4 = /ip\slink\sset\sligolo\sup/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string5 = /ip\sroute\sadd\s.{0,1000}\sdev\sligolo/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string6 = /ip\stuntap\sadd\suser\s.{0,1000}\smode\stun\sligolo/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string7 = /ligolo\-ng_agent/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string8 = /ligolo\-ng_proxy/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string9 = /ligolo\-ng\-master/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string10 = /nicocha30\/ligolo\-ng/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string11 = /nicocha30\/ligolo\-ng/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string12 = /Password\:\ssocksPass/ nocase ascii wide
        // Description: An advanced tunneling tool that uses TUN interfaces
        // Reference: https://github.com/nicocha30/ligolo-ng
        $string13 = /windows\sgo\sbuild\s\-o\sproxy\.exe\scmd\/proxy\/main\.go/ nocase ascii wide

    condition:
        any of them
}
