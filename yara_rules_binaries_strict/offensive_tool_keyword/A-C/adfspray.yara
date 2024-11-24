rule adfspray
{
    meta:
        description = "Detection patterns for the tool 'adfspray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfspray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string1 = /\s\-t\s.{0,100}https\:\/\/autodiscover\..{0,100}\/autodiscover\/autodiscover\.xml.{0,100}autodiscover/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string2 = /\s\-user\s.{0,100}\s\-\-passwordlist\s/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string3 = "/ADFSpray" nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string4 = /\[.{0,100}\]\sOverall\scompromised\saccounts\:\s/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string5 = /\[\+\]\sSeems\slike\sthe\screds\sare\svalid\:\s.{0,100}\s\:\:\s.{0,100}\son\s/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string6 = /\\ADFSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string7 = /ADFSpray\.csv/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string8 = /adfspray\.git/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string9 = /ADFSpray\.py/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string10 = "Total number of passwords to test: " nocase ascii wide
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
