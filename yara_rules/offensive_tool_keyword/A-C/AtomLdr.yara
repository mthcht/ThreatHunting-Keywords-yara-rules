rule AtomLdr
{
    meta:
        description = "Detection patterns for the tool 'AtomLdr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AtomLdr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string1 = /\/AtomLdr\.git/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string2 = /\\AtomLdr\\x64/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string3 = /AtomLdr\.dll/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string4 = /AtomLdr\.sln/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string5 = /AtomLdr\.vcxproj/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string6 = /AtomLdr\-main\.zip/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string7 = /NUL0x4C\/AtomLdr/ nocase ascii wide

    condition:
        any of them
}
