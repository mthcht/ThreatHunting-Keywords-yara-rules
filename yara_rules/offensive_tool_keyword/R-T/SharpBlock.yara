rule SharpBlock
{
    meta:
        description = "Detection patterns for the tool 'SharpBlock' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBlock"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string1 = /\s\-d\s.{0,1000}Active\sProtection\sDLL\sfor\sSylantStrike/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string2 = /\s\-\-disable\-bypass\-amsi/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string3 = /\s\-\-disable\-bypass\-cmdline/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string4 = /\s\-\-disable\-bypass\-etw/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string5 = /\/SharpSploit\// nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string6 = /\\\\\.\\pipe\\mimi/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string7 = /execute\-assembly\sSharpBlock/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string8 = /SharpBlock\s\-/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string9 = /SharpBlock\.csproj/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string10 = /SharpBlock\.exe/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string11 = /SharpBlock\.sln/ nocase ascii wide

    condition:
        any of them
}
