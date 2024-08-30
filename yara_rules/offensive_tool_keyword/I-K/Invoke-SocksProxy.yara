rule Invoke_SocksProxy
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SocksProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SocksProxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string1 = /\sproxyTunnel\.ps1/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string2 = /\/Invoke\-SocksProxy\.git/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string3 = /\/Invoke\-SocksProxy\// nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string4 = /\/proxyTunnel\.ps1/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string5 = /\\Invoke\-SocksProxy\\/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string6 = /\\proxyTunnel\.ps1/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string7 = /509e8855fc2ebcd22bd352a34ef1a0493c4cf10b488b5b2d2fece7ad168518f9/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: N/A
        $string8 = /\-Command\s\"New\-NetFirewallRule\s\-DisplayName\s\'Windows\sUpdate\'\s\-Direction\sOutbound\s\-Action\sAllow/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string9 = /e7697645f36de5978c1b640b6b3fc819e55b00ee8d9e9798919c11cc7a6fc88b/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string10 = /e7697645f36de5978c1b640b6b3fc819e55b00ee8d9e9798919c11cc7a6fc88b/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string11 = /Invoke\-ReverseSocksProxy/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string12 = /Invoke\-ReverseSocksProxy/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string13 = /Invoke\-SocksProxy\s/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string14 = /Invoke\-SocksProxy\s/ nocase ascii wide
        // Description: Creates a local or reverse Socks proxy using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string15 = /Invoke\-SocksProxy/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string16 = /Invoke\-SocksProxy\./ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string17 = /Invoke\-SocksProxy\.psm1/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/roadwy/DefenderYara/blob/9bbdb7f9fd3513ce30aa69cd1d88830e3cf596ca/Backdoor/Win64/PortStarter/Backdoor_Win64_PortStarter_B.yar#L8
        $string18 = /New\-NetFirewallRule\s\-DisplayName\s\'Windows\sUpdate\'\s\-Direction\sOutbound\s\-Action\sAllow/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string19 = /p3nt4\/Invoke\-SocksProxy/ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string20 = /ReverseSocksProxyHandler\./ nocase ascii wide
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string21 = /ReverseSocksProxyHandler\.py/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string22 = /ReverseSocksProxyHandler\.py/ nocase ascii wide

    condition:
        any of them
}
