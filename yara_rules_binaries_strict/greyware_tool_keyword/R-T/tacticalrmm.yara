rule tacticalrmm
{
    meta:
        description = "Detection patterns for the tool 'tacticalrmm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tacticalrmm"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string1 = /\srmm\-installer\.ps1/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string2 = /\stacticalrmm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string3 = /\/amidaware\/rmmagent\/releases\/download\// nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string4 = /\/nats\-rmm\.conf/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string5 = /\/rmm\/api\/tacticalrmm\// nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string6 = /\/rmm\-installer\.ps1/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string7 = /\/tacticalagent\.log/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string8 = /\/tacticalagent\-v.{0,100}\-.{0,100}\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string9 = /\/tacticalagent\-v.{0,100}\-linux\-arm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string10 = /\/tacticalagent\-v.{0,100}\-windows\-amd64\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string11 = /\/tacticalrmm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string12 = /\/tacticalrmm\.git/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string13 = /\/tacticalrmm\/master\/install\.sh/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string14 = /\/tacticalrmm\/releases\/latest/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string15 = /\/tacticalrmm\-web\.git/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string16 = /\\InventoryApplicationFile\\tacticalagent\-v2/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string17 = /\\Program\sFiles\\TacticalAgent\\/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string18 = /\\ProgramData\\TacticalRMM\\/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string19 = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string20 = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string21 = /\\rmm\-installer\.ps1/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string22 = /\\tacticalagent\-v.{0,100}\-linux\-arm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string23 = /\\tacticalagent\-v.{0,100}\-windows\-amd64\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string24 = /\\tacticalrmm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string25 = /\\tacticalrmm\\/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string26 = /amidaware\/tacticalrmm/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string27 = /https\:\/\/.{0,100}\.tacticalrmm\.com\// nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string28 = /net\sstop\stacticalrmm/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string29 = /RMM\.WebRemote\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string30 = /SOFTWARE\\TacticalRMM/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string31 = /su\s\-\stactical/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string32 = /sudo\s\-s\s\/bin\/bash\stactical/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string33 = /systemctl\s.{0,100}\srmm\.service/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string34 = /Tactical\sRMM\sAgent/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string35 = /tacticalrmm\.utils/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string36 = /tacticalrmm\-develop/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
