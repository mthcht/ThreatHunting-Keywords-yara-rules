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
        $string1 = /Invoke\-ReverseSocksProxy/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string2 = /Invoke\-SocksProxy\s/ nocase ascii wide
        // Description: Creates a local or reverse Socks proxy using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string3 = /Invoke\-SocksProxy/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string4 = /Invoke\-SocksProxy\./ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string5 = /ReverseSocksProxyHandler\./ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string6 = /ReverseSocksProxyHandler\.py/ nocase ascii wide

    condition:
        any of them
}
