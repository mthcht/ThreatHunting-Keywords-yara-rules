rule SharpCOM
{
    meta:
        description = "Detection patterns for the tool 'SharpCOM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpCOM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string1 = /\.exe\s\-\-Method\sShellWindows\s\-\-ComputerName\s.{0,1000}\s\-\-Command\s/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string2 = /\/SharpCOM\.exe/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string3 = /\/SharpCOM\.git/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string4 = /\\SharpCOM\.csproj/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string5 = /\\SharpCOM\.exe/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string6 = /\\SharpCOM\.sln/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string7 = /\>SharpCOM\</ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string8 = /0c9c1d4a02cdc9cac7b19c0b055468d9c04714c00bd3df254490ecf4953c5c95/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string9 = /51960F7D\-76FE\-499F\-AFBD\-ACABD7BA50D1/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string10 = /d01dcb5cb218aa1cf3e7e942a101d371090db7dc7a29acdd905b0932e87c6668/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string11 = /Invoke\-DCOM\.ps1/ nocase ascii wide
        // Description: DCOM Lateral Movement
        // Reference: https://github.com/rvrsh3ll/SharpCOM
        $string12 = /rvrsh3ll\/SharpCOM/ nocase ascii wide

    condition:
        any of them
}
