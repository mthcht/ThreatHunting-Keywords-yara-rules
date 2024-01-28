rule KaynStrike
{
    meta:
        description = "Detection patterns for the tool 'KaynStrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KaynStrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string1 = /\sKaynStrike\.cna/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string2 = /\/include\/KaynStrike\.h/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string3 = /\/KaynStrike\.cna/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string4 = /\/KaynStrike\.git/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string5 = /\/src\/KaynStrike\.c/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string6 = /\\include\\KaynStrike\.h/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string7 = /\\KAssembly\.x64\.o/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string8 = /\\KaynStrike\.cna/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string9 = /\\KaynStrike\\src\\/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string10 = /\\KaynStrike\-main/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string11 = /\\src\\KaynStrike\.c/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string12 = /Cracked5pider\/KaynStrike/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string13 = /KaynStrike\.x64\.bin/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string14 = /KaynStrike\.x64\.exe/ nocase ascii wide
        // Description: A User Defined Reflective Loader for Cobalt Strike Beacon that spoofs the thread start address and frees itself after entry point was executed.
        // Reference: https://github.com/Cracked5pider/KaynStrike
        $string15 = /WINAPI\sKaynLoader\(/ nocase ascii wide

    condition:
        any of them
}
