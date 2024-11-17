rule SharpExfiltrate
{
    meta:
        description = "Detection patterns for the tool 'SharpExfiltrate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExfiltrate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string1 = /\.exe\sAzureStorage\s\-\-connectionstring\s.{0,100}\s\-\-filepath\s.{0,100}\s\-\-extensions\s/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string2 = /\.exe\sGoogleDrive\s\-\-appname\s.{0,100}\s\-\-accesstoken\s.{0,100}\s\-\-filepath\s.{0,100}\s\-\-extensions\s.{0,100}\s\-\-memoryonly/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string3 = /\.exe\sOneDrive\s\-\-username\s.{0,100}\s\-\-password\s.{0,100}\s\-\-filepath\s.{0,100}\\.{0,100}\.exe/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string4 = /\/SharpExfiltrate\.git/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string5 = /\/SharpExfiltrate\// nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string6 = /\\SharpExfiltrate\\/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string7 = /3bb553cd\-0a48\-402d\-9812\-8daff60ac628/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string8 = /Flangvik\/SharpExfiltrate/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string9 = /SharpExfiltrate\.csproj/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string10 = /SharpExfiltrate\.exe/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string11 = /SharpExfiltrate\.sln/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string12 = /SharpExfiltrateLootCache/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string13 = /SharpExfiltrate\-main/ nocase ascii wide
        // Description: Modular C# framework to exfiltrate loot over secure and trusted channels.
        // Reference: https://github.com/Flangvik/SharpExfiltrate
        $string14 = /using\sSharpExfiltrate/ nocase ascii wide
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
