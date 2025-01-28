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
        $string7 = "095a6fc6a2c9647417df017fa70b182abcc68b97a8addd4e25cf302f6f2e98e4" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string8 = "3791fe80848940a320ef55ec49c9a23fffcb1b97977d0a6140df61efc6533829" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string9 = "5C3AD9AC-C62C-4AA8-BAE2-9AF920A652E3" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string10 = "6003ae86c0abcc19ae6c799724e679762ed37934ab6b5c3064f65988df64a242" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string11 = "69ad04521e133db1e34347ec9a6ecb8ea3f90272c77ce2471c3145ac33fad13b" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string12 = "FFE5AD77-8AF4-4A3F-8CE7-6BDC45565F07" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string13 = /g_hDesk\s\=\sFuncs\:\:pOpenDesktopA\(g_desktopName/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string14 = /github\.com\/rossja\/TinyNuke/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string15 = /HiddenDesktop\.cpp/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string16 = /HiddenDesktop\.exe/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string17 = "HiddenDesktop_ControlWindow" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string18 = /HVNC\s\-\sTinynuke\sClone\s\[Melted\@HF\]/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string19 = "HVNC - Tinynuke Clone" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string20 = "'M', 'E', 'L', 'T', 'E', 'D', 0" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string21 = /melted\@xmpp\.jp/ nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string22 = "Meltedd/HVNC" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string23 = "Starting HVNC Server" nocase ascii wide
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string24 = /t\.me\/Melteddd/ nocase ascii wide
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
