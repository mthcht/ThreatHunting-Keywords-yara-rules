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
        $string1 = /.{0,1000}\/AtomLdr\.git.{0,1000}/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string2 = /.{0,1000}\\AtomLdr\\x64.{0,1000}/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string3 = /.{0,1000}AtomLdr\.dll.{0,1000}/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string4 = /.{0,1000}AtomLdr\.sln.{0,1000}/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string5 = /.{0,1000}AtomLdr\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string6 = /.{0,1000}AtomLdr\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: A DLL loader with advanced evasive features
        // Reference: https://github.com/NUL0x4C/AtomLdr
        $string7 = /.{0,1000}NUL0x4C\/AtomLdr.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
