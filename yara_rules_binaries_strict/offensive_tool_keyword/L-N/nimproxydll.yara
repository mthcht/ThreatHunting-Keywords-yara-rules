rule nimproxydll
{
    meta:
        description = "Detection patterns for the tool 'nimproxydll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimproxydll"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string1 = /\screateproxydll\.sh/ nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string2 = /\/createproxydll\.sh/ nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string3 = /\/nimproxydll\.git/ nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string4 = "/nimproxydll/" nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string5 = /\\nimproxydll\\/ nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string6 = /\\nimproxydll\-main\\/ nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string7 = "17257046150e6cbdc59be7873210cc6e0399ba51a5da24114f3c147bdc4fdb4c" nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string8 = "ab1b755120b2d5fb3db73f363a0b44881bc8b5e9699e27b804c9806b78de3a1b" nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string9 = /app\/dllproxy\.nim/ nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string10 = "cyllective/nimproxydll" nocase ascii wide
        // Description: A Docker container for byt3bl33d3r/NimDllSideload - DLL sideloading/proxying
        // Reference: https://github.com/cyllective/nimproxydll
        $string11 = "make image && make proxydll" nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
