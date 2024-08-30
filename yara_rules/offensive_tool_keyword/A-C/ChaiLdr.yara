rule ChaiLdr
{
    meta:
        description = "Detection patterns for the tool 'ChaiLdr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChaiLdr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string1 = /\!\]\sAPC\sInjection\svia\sSyscalls\sfailed\!/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string2 = /\/ChaiLdr\.exe/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string3 = /\/ChaiLdr\.git/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string4 = /\\ChaiLdr\.exe/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string5 = /\\ChaiLdr\-main/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string6 = /06a80d02597302885c6a7ed373187e751e82878f71826962e0c09e74647326d5/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string7 = /0cd8f2bd40fdca1eb41c8317b86b1382f1cbf57e2a7537fd731c8541132bef60/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string8 = /658318b022bfa0408ef73d5a1333cdfc5fec5295a0aaa75c81b54f46b5d87ad8/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string9 = /6746881860057860fe384c046a89cdf6f5e3bbd014793b6e0d029f160b4119cf/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string10 = /9ea66594805d5e7b8a1abc876f99d7ce1de87936902a3f7726f5f0188778c874/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string11 = /c030cc4102e6bd16e8f55a5030a440f6ee5f411ad86b1c3af56b44e53cda14f6/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string12 = /cd4d53a9\-2db8\-4408\-90a0\-896b2bc4c9f8/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string13 = /Cipher7\/ChaiLdr/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string14 = /syswhispers\-apc\.c/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string15 = /syswhispers\-apc\.h/ nocase ascii wide
        // Description: Indirect syscalls AV bypass
        // Reference: https://github.com/Cipher7/ChaiLdr
        $string16 = /syswhispers\-apc\-asm\.x64\.asm/ nocase ascii wide

    condition:
        any of them
}
