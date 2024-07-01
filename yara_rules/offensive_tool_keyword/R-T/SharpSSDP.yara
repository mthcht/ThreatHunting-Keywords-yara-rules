rule SharpSSDP
{
    meta:
        description = "Detection patterns for the tool 'SharpSSDP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSSDP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string1 = /\/SharpSSDP\.git/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string2 = /\/SharpSSDP\// nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string3 = /\\SharpSSDP\.csproj/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string4 = /\\SharpSSDP\.sln/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string5 = /\\SharpSSDP\\/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string6 = /2c03dc7ed9a0770af9e8ba9c8fffa0e8b8ffcdf1f7efe5d2d33a32fe736989cd/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string7 = /583409661e2afdf55553b7da2e510aef9cd10c542d98ebc4ee1962d1d4472bc1/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string8 = /6E383DE4\-DE89\-4247\-A41A\-79DB1DC03AAA/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string9 = /cddd9cbec4525bc73c44a2c154b12372210e9ccedb9cafd7c495a590c481f6a8/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string10 = /namespace\sSharpSSDP/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string11 = /rvrsh3ll\/SharpSSDP/ nocase ascii wide
        // Description:  execute SharpSSDP.exe through Cobalt Strike's Beacon "execute-assembly" module to discover SSDP related services
        // Reference: https://github.com/rvrsh3ll/SharpSSDP
        $string12 = /SharpSSDP\.exe/ nocase ascii wide

    condition:
        any of them
}
