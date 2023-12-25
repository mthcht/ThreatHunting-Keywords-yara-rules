rule nircmd
{
    meta:
        description = "Detection patterns for the tool 'nircmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nircmd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string1 = /\snircmd\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string2 = /\snircmdc\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string3 = /\/nircmd\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string4 = /\/nircmd\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string5 = /\/nircmdc\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string6 = /\/nircmd\-x64\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string7 = /\\nircmd\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string8 = /\\nircmd\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string9 = /\\nircmdc\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string10 = /\\nircmd\-x64\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string11 = /nircmd\.exe\s/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string12 = /nircmdc\.exe\s/ nocase ascii wide

    condition:
        any of them
}
