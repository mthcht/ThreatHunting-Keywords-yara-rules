rule SharpSocks
{
    meta:
        description = "Detection patterns for the tool 'SharpSocks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string1 = /.{0,1000}\s\-\-beacon\=.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string2 = /.{0,1000}\s\-\-payloadcookie\s.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string3 = /.{0,1000}\/SharpSocks.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string4 = /.{0,1000}\-\-payload\-cookie.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string5 = /.{0,1000}ProcessCommandChannelImplantMessage.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string6 = /.{0,1000}ProcessEncryptedC2Request.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string7 = /.{0,1000}SharpSocks\.exe.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string8 = /.{0,1000}SharpSocks\.pfx.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string9 = /.{0,1000}SharpSocks\.resx.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string10 = /.{0,1000}SharpSocks\.sln.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string11 = /.{0,1000}SharpSocksCommon.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string12 = /.{0,1000}SharpSocksConfig.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string13 = /.{0,1000}SharpSocksImplant.{0,1000}/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string14 = /.{0,1000}SharpSocksServer.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
