rule BobTheSmuggler
{
    meta:
        description = "Detection patterns for the tool 'BobTheSmuggler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BobTheSmuggler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string1 = /\sSharpHound\.html/ nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string2 = /\/BobTheSmuggler\.git/ nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string3 = /\\SharpHound\.html/ nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string4 = /BobTheSmuggler\.py/ nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string5 = "BobTheSmuggler-main" nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string6 = "Getting the Obfuscated JS Code" nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string7 = "Successfully embedded EXE into GIF" nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string8 = "Successfully embedded EXE into PNG" nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string9 = "TheCyb3rAlpha/BobTheSmuggler" nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string10 = "URL must be provided for GIF embedding!" nocase ascii wide
        // Description: HTML SMUGGLING TOOL 6 allows you to create HTML files with embedded 7z/zip archives. The tool would compress your binary (EXE/DLL) into 7z/zip file format then XOR encrypt the archive and then hides inside PNG/GIF image file format (Image Polyglots)
        // Reference: https://github.com/TheCyb3rAlpha/BobTheSmuggler
        $string11 = "URL must be provided for PNG embedding!" nocase ascii wide
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
