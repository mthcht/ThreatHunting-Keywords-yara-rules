rule donut
{
    meta:
        description = "Detection patterns for the tool 'donut' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "donut"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string1 = /.{0,1000}\s\-a\s1\s\-f\s.{0,1000}\.dll\s\-p\shttp.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string2 = /.{0,1000}\s\-DDONUT_EXE\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string3 = /.{0,1000}\sDisableETW\(.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string4 = /.{0,1000}\sDisableWLDP\(.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string5 = /.{0,1000}\sdonut\.c\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string6 = /.{0,1000}\sdonut\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string7 = /.{0,1000}\sdonut\.o\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string8 = /.{0,1000}\s\-u\shttp.{0,1000}\s\-f\s.{0,1000}\.dll\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string9 = /.{0,1000}\/donut\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string10 = /.{0,1000}\/donut\.exe.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string11 = /.{0,1000}\/donut\.git/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string12 = /.{0,1000}\/donutmodule\.c.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string13 = /.{0,1000}\/DonutTest\/.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string14 = /.{0,1000}\/loader\/bypass\.c/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string15 = /.{0,1000}\/loader\/bypass\.h/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string16 = /.{0,1000}\\donut\.exe.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string17 = /.{0,1000}DisableAMSI\(.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string18 = /.{0,1000}docker.{0,1000}\sdonut\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string19 = /.{0,1000}donut.{0,1000}\s\\DemoCreateProcess\.dll\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string20 = /.{0,1000}donut\.exe\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string21 = /.{0,1000}DONUT_BYPASS_CONTINUE.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string22 = /.{0,1000}DonutLoader\(.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string23 = /.{0,1000}donut\-payload\..{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string24 = /.{0,1000}donut\-shellcode.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string25 = /.{0,1000}go\-donut\/.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string26 = /.{0,1000}go\-donut\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string27 = /.{0,1000}InternetCrackUrl.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string28 = /.{0,1000}loader\/inject\.c.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string29 = /.{0,1000}loader\/inject_local\.c.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string30 = /.{0,1000}loader_exe_x64\..{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string31 = /.{0,1000}loader_exe_x86\..{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string32 = /.{0,1000}nmake\sinject_local\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string33 = /.{0,1000}PDONUT_INSTANCE.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string34 = /.{0,1000}ProcessManager\.exe\s\-\-machine\s.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string35 = /.{0,1000}ProcessManager\.exe\s\-\-name\sexplorer.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string36 = /.{0,1000}therealwover\@protonmail\.com.{0,1000}/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string37 = /.{0,1000}thewover\/donut.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
