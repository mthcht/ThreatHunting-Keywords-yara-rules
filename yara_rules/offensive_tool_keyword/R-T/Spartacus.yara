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
        $string1 = /\s\-\-action\sexports\s\-\-dll\sC\:\\Windows\\System32\\amsi\.dll/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string2 = /\s\-\-dll\s.{0,1000}\s\-\-only\s.{0,1000}AmsiScanBuffer.{0,1000}AmsiScanString/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string3 = /\s\-\-dll\sC\:\\Windows\\System32\\version\.dll.{0,1000}\-\-dll\sC\:\\Windows\\System32\\userenv\.dll/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string4 = /\s\-\-mode\sproxy\s\-\-ghidra\s.{0,1000}\-\-dll\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string5 = /\\tmp\\dll\-collection/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string6 = /Accenture\/Spartacus/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string7 = /Assets\/solution\/dllmain\.cpp/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string8 = /Data\\VulnerableCOM\.csv/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string9 = /exports\s\-\-dll\s.{0,1000}\.dll\s\-\-prototypes\s\.\/Assets\/prototypes\.csv/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string10 = /help\\dll\.txt/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string11 = /\-\-mode\scom\s\-\-acl\s\-\-csv\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string12 = /\-\-mode\scom\s\-\-procmon\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string13 = /\-\-mode\sdll\s\-\-existing\s\-\-pml\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string14 = /\-\-mode\sdll\s\-\-procmon\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string15 = /\-\-mode\sproxy\s\-\-action\sprototypes\s\-\-path\s.{0,1000}prototypes\.csv/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string16 = /\-\-mode\sproxy\s\-\-dll\s.{0,1000}\.dll.{0,1000}\-\-external\-resources/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string17 = /\-\-mode\sproxy\s\-\-ghidra\s.{0,1000}\-\-dll\s/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string18 = /Spartacus\.exe\s\-\-mode\sproxy/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string19 = /Spartacus\-main\.zip/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string20 = /spartacus\-proxy\-.{0,1000}\.log/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://github.com/Accenture/Spartacus
        $string21 = /Spartacus\-v2\..{0,1000}\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}
