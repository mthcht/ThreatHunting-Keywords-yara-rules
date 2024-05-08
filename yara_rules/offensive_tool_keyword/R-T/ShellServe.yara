rule ShellServe
{
    meta:
        description = "Detection patterns for the tool 'ShellServe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellServe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string1 = /\/ShellServe\.git/ nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string2 = /\@author\s7etsuo/ nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string3 = /7c8c4d1e312218cb8a31c00d67f3b5e2e752d9e094e37c959e35e0483fc69109/ nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string4 = /7etsuo\/ShellServe/ nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string5 = /d1f5e8ada7197e67b7bdede4827104e286c63f24407bb9eef80cc7c2bd2e065f/ nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string6 = /edaa2e28eee643e72776396155001db13f288d9bc64e57057127a09c1d57c9a7/ nocase ascii wide
        // Description: Multi-client network fileserver with integrated shell functionality crafted in C using system calls for efficient and direct file and command processing
        // Reference: https://github.com/7etsuo/ShellServe
        $string7 = /load_credentials\(\"credentials\.txt\"\)/ nocase ascii wide

    condition:
        any of them
}
