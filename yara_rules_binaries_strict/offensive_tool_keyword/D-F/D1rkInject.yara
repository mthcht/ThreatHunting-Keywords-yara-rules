rule D1rkInject
{
    meta:
        description = "Detection patterns for the tool 'D1rkInject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D1rkInject"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string1 = /\/D1rkInject\.git/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string2 = /\/MalStuff\.cpp/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string3 = /\\D1rkInject\\/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string4 = /\\MalStuff\.cpp/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string5 = /APT\sstands\sfor\sAdvanced\sPersistence\sTomato/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string6 = /BD602C80\-47ED\-4294\-B981\-0119D2200DB8/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string7 = /D1rkInject\.cpp/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string8 = /D1rkInject\.exe/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string9 = /D1rkInject\.iobj/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string10 = /D1rkInject\.log/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string11 = /D1rkInject\.sln/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string12 = /D1rkInject\.vcxproj/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string13 = /D1rkInject\-main/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string14 = /EEC35BCF\-E990\-4260\-828D\-2B4F9AC97269/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string15 = /TheD1rkMtr\/D1rkInject/ nocase ascii wide
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
