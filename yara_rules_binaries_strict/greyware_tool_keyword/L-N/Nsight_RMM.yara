rule Nsight_RMM
{
    meta:
        description = "Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nsight RMM"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string1 = /\supload.{0,100}\.systemmonitor\.eu\.com.{0,100}\/command\/agentprocessor/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string2 = /\\Advanced\sMonitoring\sAgent\\debug\.log/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string3 = /\\Advanced\sMonitoring\sAgent\\staging/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string4 = /\\Advanced\sMonitoring\sAgent\\task_start\.js/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string5 = /\\Advanced\sMonitoring\sAgent\\unzip\.exe/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string6 = /\\Advanced\sMonitoring\sAgent\\winagent\.exe/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string7 = /\\Program\sFiles\s\(x86\)\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string8 = /\\Program\sFiles\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string9 = /\\Start\sMenu\\Programs\\Advanced\sMonitoring\sAgent\.lnk/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string10 = /Advanced\sMonitoring\sAgent\sHTTP\sRetriever\s1\.1/ nocase ascii wide
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
