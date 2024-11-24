rule SharpHide
{
    meta:
        description = "Detection patterns for the tool 'SharpHide' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpHide"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string1 = /\/SharpHide\.git/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string2 = /\/SharpHide\.git/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string3 = /\[\+\]\sSharpHide\srunning\sas\selevated\suser/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string4 = /\[\+\]\sSharpHide\srunning\sas\snormal\suser/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string5 = /\\Windows\\Temp\\Bla\.exe/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string6 = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string7 = "66504e8c044a01ed3ef2a97dd36de68b7b1913d737d6ad4e6bd7778d80dec92f" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string8 = "6ff0ec2a775575ab2724c254aa386c44155453c1ae020446a6fb5b0535de65d3" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string9 = "outflanknl/SharpHide" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string10 = "SharpHide running as elevated user" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string11 = /SharpHide\.csproj/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string12 = /SharpHide\.exe/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string13 = /SharpHide\.sln/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string14 = "SharpHide-master" nocase ascii wide
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
