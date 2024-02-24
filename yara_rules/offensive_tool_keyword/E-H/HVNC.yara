rule HVNC
{
    meta:
        description = "Detection patterns for the tool 'HVNC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HVNC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string1 = /\/HVNC\.git/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string2 = /\\HiddenDesktop\.h/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string3 = /\\hvnc\.exe/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string4 = /\\HVNC\.sln/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string5 = /\\HVNC\.vcxproj/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string6 = /\\HVNC\-main\.zip/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string7 = /5C3AD9AC\-C62C\-4AA8\-BAE2\-9AF920A652E3/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string8 = /FFE5AD77\-8AF4\-4A3F\-8CE7\-6BDC45565F07/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string9 = /g_hDesk\s\=\sFuncs\:\:pOpenDesktopA\(g_desktopName/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string10 = /github\.com\/rossja\/TinyNuke/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string11 = /HiddenDesktop\.cpp/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string12 = /HiddenDesktop\.exe/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string13 = /HiddenDesktop_ControlWindow/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string14 = /HVNC\s\-\sTinynuke\sClone/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string15 = /\'M\'\,\s\'E\'\,\s\'L\'\,\s\'T\'\,\s\'E\'\,\s\'D\'\,\s0/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string16 = /melted\@xmpp\.jp/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string17 = /Meltedd\/HVNC/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string18 = /Starting\sHVNC\sServer/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string19 = /t\.me\/Melteddd/ nocase ascii wide

    condition:
        any of them
}
