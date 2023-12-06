rule exe_to_dll
{
    meta:
        description = "Detection patterns for the tool 'exe_to_dll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exe_to_dll"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string1 = /\/exe_to_dll\.git/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string2 = /\/exe_to_dll\.git/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string3 = /\/pe2shc\.exe/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string4 = /\\exe_to_dll\\/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string5 = /exe_to_dll\.exe/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string6 = /exe_to_dll\.exe/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string7 = /exe_to_dll_.{0,1000}\.zip/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string8 = /exe_to_dll_.{0,1000}_32bit\.zip/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string9 = /exe_to_dll_.{0,1000}_64bit\.zip/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string10 = /exe_to_dll\-master/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string11 = /exe_to_dll\-master/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string12 = /hasherezade\/exe_to_dll/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string13 = /hasherezade\/exe_to_dll/ nocase ascii wide

    condition:
        any of them
}
