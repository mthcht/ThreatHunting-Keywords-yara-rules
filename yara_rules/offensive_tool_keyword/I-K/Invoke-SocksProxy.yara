rule Invoke_SocksProxy
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SocksProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SocksProxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string1 = /.{0,1000}Invoke\-ReverseSocksProxy.{0,1000}/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string2 = /.{0,1000}Invoke\-SocksProxy\s.{0,1000}/ nocase ascii wide
        // Description: Creates a local or reverse Socks proxy using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string3 = /.{0,1000}Invoke\-SocksProxy.{0,1000}/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string4 = /.{0,1000}Invoke\-SocksProxy\..{0,1000}/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string5 = /.{0,1000}ReverseSocksProxyHandler\..{0,1000}/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string6 = /.{0,1000}ReverseSocksProxyHandler\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
