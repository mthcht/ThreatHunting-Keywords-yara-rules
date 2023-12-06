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
        $string1 = /\s\-\-beacon\=/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string2 = /\s\-\-payloadcookie\s/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string3 = /\/SharpSocks/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string4 = /\-\-payload\-cookie/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string5 = /ProcessCommandChannelImplantMessage/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string6 = /ProcessEncryptedC2Request/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string7 = /SharpSocks\.exe/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string8 = /SharpSocks\.pfx/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string9 = /SharpSocks\.resx/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string10 = /SharpSocks\.sln/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string11 = /SharpSocksCommon/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string12 = /SharpSocksConfig/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string13 = /SharpSocksImplant/ nocase ascii wide
        // Description: Tunnellable HTTP/HTTPS socks4a proxy written in C# and deployable via PowerShell
        // Reference: https://github.com/nettitude/SharpSocks
        $string14 = /SharpSocksServer/ nocase ascii wide

    condition:
        any of them
}
