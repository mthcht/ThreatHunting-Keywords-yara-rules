rule SharpSC
{
    meta:
        description = "Detection patterns for the tool 'SharpSC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string1 = /\.exe\saction\=create\s.{0,100}\sservice\=.{0,100}\sdisplayname\=.{0,100}\sbinpath\=.{0,100}/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string2 = /\/SharpSC\.exe/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string3 = /\/SharpSC\.git/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string4 = /\\SharpSC\.exe/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string5 = /\\SharpSC\-main/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string6 = /3b6a44069c343b15c9bafec9feb7d5597f936485c68f29316e96fe97aa15d06d/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string7 = /3D9D679D\-6052\-4C5E\-BD91\-2BC3DED09D0A/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string8 = /4c0fdf591ecec6aaeb3b6529f7b3800125910f16bc23496ba279a4bee0c2361c/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string9 = /9870daa238c3cab7fa949a1f8b80d3451c78eb07d18030ad061d8b91d612decc/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string10 = /djhohnstein\/SharpSC/ nocase ascii wide
        // Description: .NET assembly to interact with services. (included in powershell empire)
        // Reference: https://github.com/djhohnstein/SharpSC
        $string11 = /namespace\sSharpSC/ nocase ascii wide
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
