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
        $string1 = /.{0,1000}\s\-d\s.{0,1000}Active\sProtection\sDLL\sfor\sSylantStrike.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string2 = /.{0,1000}\s\-\-disable\-bypass\-amsi.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string3 = /.{0,1000}\s\-\-disable\-bypass\-cmdline.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string4 = /.{0,1000}\s\-\-disable\-bypass\-etw.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string5 = /.{0,1000}\/SharpSploit\/.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string6 = /.{0,1000}\\\\\.\\pipe\\mimi.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string7 = /.{0,1000}execute\-assembly\sSharpBlock.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string8 = /.{0,1000}SharpBlock\s\-.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string9 = /.{0,1000}SharpBlock\.csproj.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string10 = /.{0,1000}SharpBlock\.exe.{0,1000}/ nocase ascii wide
        // Description: A method of bypassing EDR active projection DLL by preventing entry point exection
        // Reference: https://github.com/CCob/SharpBlock
        $string11 = /.{0,1000}SharpBlock\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
