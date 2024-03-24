rule SharpHose
{
    meta:
        description = "Detection patterns for the tool 'SharpHose' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpHose"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string1 = /\s\-\-action\sSPRAY_USERS\s/ nocase ascii wide
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string2 = /\sSharpHose\.exe/ nocase ascii wide
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string3 = /\s\-\-spraypassword\s/ nocase ascii wide
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string4 = /\/SharpHose\.exe/ nocase ascii wide
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string5 = /\\SharpHose\.exe/ nocase ascii wide
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string6 = /\\SharpHose\\Program\.cs/ nocase ascii wide
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string7 = /29d30b556932d0657f14a0b290ec79d23f88d8454ca27151c8348ab7e4be9657/ nocase ascii wide
        // Description: Asynchronous Password Spraying Tool in C# for Windows Environments
        // Reference: https://github.com/ustayready/SharpHose
        $string8 = /51C6E016\-1428\-441D\-82E9\-BB0EB599BBC8/ nocase ascii wide

    condition:
        any of them
}
