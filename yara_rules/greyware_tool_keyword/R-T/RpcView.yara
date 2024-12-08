rule RpcView
{
    meta:
        description = "Detection patterns for the tool 'RpcView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RpcView"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string1 = /\\RpcView\.exe/ nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string2 = /\\RpcView64\.7z/ nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string3 = "0d2d07010e3ad3219d37b9a10a04abf50bd84c6c429b96aab5aad70f31c42efe" nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string4 = "a1d89c9d81a2e9c7558e8f0c91ec8652d40af94726f3125f9fe31206adb528de" nocase ascii wide
        // Description: RpcView is a free tool to explore and decompile Microsoft RPC interfaces
        // Reference: https://github.com/silverf0x/RpcView
        $string5 = "silverf0x/RpcView" nocase ascii wide

    condition:
        any of them
}
