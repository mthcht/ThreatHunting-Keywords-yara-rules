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
        $string1 = /.{0,1000}\/exe_to_dll\.git.{0,1000}/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string2 = /.{0,1000}\/exe_to_dll\.git.{0,1000}/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string3 = /.{0,1000}\/pe2shc\.exe.{0,1000}/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string4 = /.{0,1000}\\exe_to_dll\\.{0,1000}/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string5 = /.{0,1000}exe_to_dll\.exe.{0,1000}/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string6 = /.{0,1000}exe_to_dll\.exe.{0,1000}/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string7 = /.{0,1000}exe_to_dll_.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string8 = /.{0,1000}exe_to_dll_.{0,1000}_32bit\.zip.{0,1000}/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string9 = /.{0,1000}exe_to_dll_.{0,1000}_64bit\.zip.{0,1000}/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string10 = /.{0,1000}exe_to_dll\-master.{0,1000}/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string11 = /.{0,1000}exe_to_dll\-master.{0,1000}/ nocase ascii wide
        // Description: Converts a EXE into DLL
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string12 = /.{0,1000}hasherezade\/exe_to_dll.{0,1000}/ nocase ascii wide
        // Description: Converts an EXE so that it can be loaded like a DLL.
        // Reference: https://github.com/hasherezade/exe_to_dll
        $string13 = /.{0,1000}hasherezade\/exe_to_dll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
