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
        $string1 = /\s\-a\s1\s\-f\s.{0,100}\.dll\s\-p\shttp/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string2 = " -DDONUT_EXE " nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string3 = /\sDisableETW\(/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string4 = /\sDisableWLDP\(/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string5 = /\sdonut\.c\s/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string6 = /\sdonut\.exe\s/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string7 = /\sdonut\.o\s/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string8 = /\s\-u\shttp.{0,100}\s\-f\s.{0,100}\.dll\s.{0,100}\s\-p\s/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string9 = /\/donut\s.{0,100}\.exe/
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string10 = /\/donut\.exe/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string11 = /\/donut\.git/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string12 = /\/donutmodule\.c/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string13 = "/DonutTest/" nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string14 = /\/loader\/bypass\.c/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string15 = /\/loader\/bypass\.h/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string16 = /\\donut\.exe/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string17 = /DisableAMSI\(/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string18 = /docker.{0,100}\sdonut\s/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string19 = /donut.{0,100}\s\\DemoCreateProcess\.dll\s/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string20 = /donut\.exe\s.{0,100}\.exe/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string21 = "DONUT_BYPASS_CONTINUE" nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string22 = /DonutLoader\(/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string23 = /donut\-payload\./ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string24 = "donut-shellcode" nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string25 = /go\-donut\/.{0,100}\.exe/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string26 = /go\-donut\/.{0,100}\.go/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string27 = /loader\/inject\.c/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string28 = /loader\/inject_local\.c/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string29 = /loader_exe_x64\./ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string30 = /loader_exe_x86\./ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string31 = "nmake inject_local " nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string32 = "PDONUT_INSTANCE" nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string33 = /ProcessManager\.exe\s\-\-machine\s/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string34 = /ProcessManager\.exe\s\-\-name\sexplorer/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string35 = /therealwover\@protonmail\.com/ nocase ascii wide
        // Description: Donut is a position-independent code that enables in-memory execution of VBScript. JScript. EXE. DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself
        // Reference: https://github.com/TheWover/donut
        $string36 = "thewover/donut" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
