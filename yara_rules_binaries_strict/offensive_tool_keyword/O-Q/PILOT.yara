rule PILOT
{
    meta:
        description = "Detection patterns for the tool 'PILOT' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PILOT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string1 = /\#\sAuthor\:\sDahvid\sSchloss\sa\.k\.a\sAPT\sBig\sDaddy/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string2 = /\/PILOT\/ATC\.py/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string3 = /\/PILOT\/PILOT\.ps1/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string4 = /\\PILOT\.ps1/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string5 = /\\PILOT\\ATC\.py/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string6 = "4870b4163315fa666dea8be03176d76aa215fe33187db45aca984e07b25ca827" nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string7 = "810950f1d775ffa916c75a85c79bb2a46f7c7250986be7748bfae90b04b33551" nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string8 = "Create a raw socket to listen for ICMP packets cause f scappy we don't need that shit" nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string9 = /dahvid\.schloss\@echeloncyber\.com/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string10 = "dahvidschloss/PILOT" nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string11 = /Listening\sfor\sincoming\sICMP\spackets\.\.\./ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string12 = "run-pilot -targetIP " nocase ascii wide
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
