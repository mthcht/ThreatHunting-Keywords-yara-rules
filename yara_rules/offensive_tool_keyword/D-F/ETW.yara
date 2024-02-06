rule ETW
{
    meta:
        description = "Detection patterns for the tool 'ETW' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ETW"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: stop ETW from giving up your loaded .NET assemblies to that pesky EDR but can't be bothered patching memory? Just pass COMPlus_ETWEnabled=0 as an environment variable during your CreateProcess call
        // Reference: https://gist.github.com/xpn/64e5b6f7ad370c343e3ab7e9f9e22503
        $string1 = /\$env\:COMPlus_ETWEnabled\=0/ nocase ascii wide
        // Description: stop ETW from giving up your loaded .NET assemblies to that pesky EDR but can't be bothered patching memory? Just pass COMPlus_ETWEnabled=0 as an environment variable during your CreateProcess call
        // Reference: https://gist.github.com/xpn/64e5b6f7ad370c343e3ab7e9f9e22503
        $string2 = /COMPlus_ETWEnabled\=0\\0\\0\\0/ nocase ascii wide
        // Description: stop ETW from giving up your loaded .NET assemblies to that pesky EDR but can't be bothered patching memory? Just pass COMPlus_ETWEnabled=0 as an environment variable during your CreateProcess call
        // Reference: https://gist.github.com/xpn/64e5b6f7ad370c343e3ab7e9f9e22503
        $string3 = /env_var_spoofing_poc\.cpp/ nocase ascii wide
        // Description: stop ETW from giving up your loaded .NET assemblies to that pesky EDR but can't be bothered patching memory? Just pass COMPlus_ETWEnabled=0 as an environment variable during your CreateProcess call
        // Reference: https://gist.github.com/xpn/64e5b6f7ad370c343e3ab7e9f9e22503
        $string4 = /set\sCOMPlus_ETWEnabled\=0/ nocase ascii wide

    condition:
        any of them
}
