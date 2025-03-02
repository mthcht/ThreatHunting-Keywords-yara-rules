rule SharpExfil
{
    meta:
        description = "Detection patterns for the tool 'SharpExfil' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExfil"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string1 = /\/SharpExfil\.git/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string2 = /\/Upload\-OneDrive\.exe/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string3 = /\\Upload\-OneDrive\.csproj/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string4 = /\\Upload\-OneDrive\.exe/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string5 = /\\Upload\-OneDrive\.sln/ nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string6 = ">Upload-OneDrive<" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string7 = "1723ab71aa08741de80ab99fa08291b4066e632466c47ade2884b3739bf244b0" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string8 = "5de78ea9-73a8-4c53-9d5e-3a893e439a3a" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string9 = "adm1nPanda/SharpExfil" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string10 = "f7ff8ee96535ad845f70c8a978366b33d7934132dda00de017fa5b09fd11a55a" nocase ascii wide
        // Description: C# executables to extract information from target environment using OneDrive API.
        // Reference: https://github.com/adm1nPanda/SharpExfil
        $string11 = /https\:\/\/graph\.microsoft\.com\/v1\.0\/drive\/root\:\/testfoldera\/\{file_name\}\:\/createUploadSession/ nocase ascii wide
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
