rule pywhisker
{
    meta:
        description = "Detection patterns for the tool 'pywhisker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pywhisker"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string1 = /\s\-u\s.{0,100}\s\-d\s.{0,100}\s\-\-dc\-ip\s.{0,100}\s\-k\s\-\-no\-pass\s\-\-target\s.{0,100}\s\-\-action\s\\"list\\"/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string2 = /\.py\s\-d\s\\"test\.local\\"\s\-u\s\\"john\\"\s\-p\s\\"password123\\"\s\-\-target\s\\"user2\\"\s\-\-action\s\\"list\\"\s\-\-dc\-ip\s\\"10\.10\.10\.1\\"/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string3 = /\.py\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-target\s.{0,100}\s\-\-action\s\s.{0,100}\s\-\-export\sPEM/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string4 = /\.py\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-target\s.{0,100}\s\-\-action\s\\"add\\"\s\-\-filename\s.{0,100}\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string5 = /\.py\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-target\s.{0,100}\s\-\-action\s\\"clear\\".{0,100}\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string6 = /\.py\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-target\s.{0,100}\s\-\-action\s\\"info\\"\s\-\-device\-id\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string7 = /\.py\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-target\s.{0,100}\s\-\-action\s\\"list\\"\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string8 = /\.py\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-target\s.{0,100}\s\-\-action\s\\"remove\\"\s\-\-device\-id\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string9 = /\/pywhisker\.git/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string10 = /getnthash\.py\s\-key\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string11 = /gettgtpkinit\.py\s\-cert\-pfx\s/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string12 = /Initializing\sdomainDumper\(\)/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string13 = /lmhash.{0,100}aad3b435b51404eeaad3b435b51404ee/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string14 = /pywhisker\.py/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string15 = /pywhisker\-main/ nocase ascii wide
        // Description: Python version of the C# tool for Shadow Credentials attacks
        // Reference: https://github.com/ShutdownRepo/pywhisker
        $string16 = /ShutdownRepo\/pywhisker/ nocase ascii wide
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
