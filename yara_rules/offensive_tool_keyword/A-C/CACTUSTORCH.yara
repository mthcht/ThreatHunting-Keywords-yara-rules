rule CACTUSTORCH
{
    meta:
        description = "Detection patterns for the tool 'CACTUSTORCH' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CACTUSTORCH"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string1 = /\sCACTUSTORCH\.cna/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string2 = /\/CACTUSTORCH\.git/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string3 = "1cccdb0227ae73ae4c712460d12cf2fb9316568f2f8ceae6e6e3e101a8552942" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string4 = "60c72ba7ed39768fd066dda3fdc75bcb5fae6efb3a0b222a3f455526dcf08c96" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string5 = /CACTUSTORCH\.hta/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string6 = /CACTUSTORCH\.js/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string7 = /CACTUSTORCH\.vba/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string8 = /CACTUSTORCH\.vbe/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string9 = /CACTUSTORCH\.vbs/ nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string10 = "d9ce9dfbdd4f95ad01fc05855235d6894ef878d6d02706e6c91720ee8a4fb5bf" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string11 = "mdsecactivebreach/CACTUSTORCH" nocase ascii wide
        // Description: A JavaScript and VBScript shellcode launcher. This will spawn a 32 bit version of the binary specified and inject shellcode into it.
        // Reference: https://github.com/mdsecactivebreach/CACTUSTORCH
        $string12 = "TM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAACf0hwW27NyRduzckXbs3JFZvzkRdqz" nocase ascii wide

    condition:
        any of them
}
