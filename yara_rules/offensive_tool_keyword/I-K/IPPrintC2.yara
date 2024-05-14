rule IPPrintC2
{
    meta:
        description = "Detection patterns for the tool 'IPPrintC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IPPrintC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string1 = /\"IPPrint\sC2\sServer\"/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string2 = /\$C2ExternalIP/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string3 = /\$EncodedCommandExfil/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string4 = /\$IPPrintC2/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string5 = /\/IPPrintC2\.git/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string6 = /4c02774a5edb8a559beebcb64833177a893b49fb8eb9bfd2e650155a207c7ba7/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string7 = /826c1daf512bcd2152b6328fc55b1ed403ed41fd1a6fc1afa6e35f34e4b9f8bc/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string8 = /c\:\\temp\\c2\.pdf/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string9 = /d222451147be2256c701679975cd45993377032f1d6afff27533bafda10c2afa/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string10 = /Diverto\/IPPrintC2/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string11 = /Invoke\-DatatExfiltration/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string12 = /Invoke\-FileC2Output/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string13 = /Invoke\-ReadC2Output/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string14 = /IPPrintC2\.ps1/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string15 = /Where\sdo\syou\swant\sto\sstore\sPDF\sC2\soutput\s/ nocase ascii wide

    condition:
        any of them
}
