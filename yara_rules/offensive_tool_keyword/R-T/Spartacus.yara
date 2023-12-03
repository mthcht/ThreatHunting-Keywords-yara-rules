rule Spartacus
{
    meta:
        description = "Detection patterns for the tool 'Spartacus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spartacus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string1 = /.{0,1000}\s\-\-action\sexports\s\-\-dll\sC:\\Windows\\System32\\amsi\.dll.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string2 = /.{0,1000}\s\-\-dll\s.{0,1000}\s\-\-only\s.{0,1000}AmsiScanBuffer.{0,1000}AmsiScanString.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string3 = /.{0,1000}\s\-\-dll\sC:\\Windows\\System32\\version\.dll.{0,1000}\-\-dll\sC:\\Windows\\System32\\userenv\.dll.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string4 = /.{0,1000}\s\-\-mode\sproxy\s\-\-ghidra\s.{0,1000}\-\-dll\s.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string5 = /.{0,1000}\\tmp\\dll\-collection.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string6 = /.{0,1000}Accenture\/Spartacus.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string7 = /.{0,1000}Assets\/solution\/dllmain\.cpp.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string8 = /.{0,1000}Data\\VulnerableCOM\.csv.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string9 = /.{0,1000}exports\s\-\-dll\s.{0,1000}\.dll\s\-\-prototypes\s\.\/Assets\/prototypes\.csv.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string10 = /.{0,1000}help\\dll\.txt.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string11 = /.{0,1000}\-\-mode\scom\s\-\-acl\s\-\-csv\s.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string12 = /.{0,1000}\-\-mode\scom\s\-\-procmon\s.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string13 = /.{0,1000}\-\-mode\sdll\s\-\-existing\s\-\-pml\s.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string14 = /.{0,1000}\-\-mode\sdll\s\-\-procmon\s.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string15 = /.{0,1000}\-\-mode\sproxy\s\-\-action\sprototypes\s\-\-path\s.{0,1000}prototypes\.csv.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string16 = /.{0,1000}\-\-mode\sproxy\s\-\-dll\s.{0,1000}\.dll.{0,1000}\-\-external\-resources.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string17 = /.{0,1000}\-\-mode\sproxy\s\-\-ghidra\s.{0,1000}\-\-dll\s.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string18 = /.{0,1000}Spartacus\.exe\s\-\-mode\sproxy.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string19 = /.{0,1000}Spartacus\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string20 = /.{0,1000}spartacus\-proxy\-.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string21 = /.{0,1000}Spartacus\-v2\..{0,1000}\-x64\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
