rule BarracudaRMM
{
    meta:
        description = "Detection patterns for the tool 'BarracudaRMM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BarracudaRMM"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string1 = /\.apitest\.barracudamsp\.com/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string2 = /\/Applications\/Managed\sWorkplace\/Onsite\sManager\/logs\// nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string3 = /\\BRMM_2024\.1\-Release/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string4 = /\\MWDiagnosticCollector\.exe/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string5 = /\\MWDiagnosticCollectorResult_.{0,100}\.zip/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string6 = /\\Program\sFiles\s\(x86\)\\Barracuda\sRMM\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string7 = /\\Program\sFiles\s\(x86\)\\Level\sPlatforms\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string8 = /\\Program\sFiles\\Barracuda\sRMM\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string9 = /\\Program\sFiles\\Level\sPlatforms\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string10 = /\\ProgramData\\Barracuda\sMSP\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string11 = /\\SOFTWARE\\Level\sPlatforms\\Managed\sWorkplace\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string12 = /\>Barracuda\sMSP\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string13 = /\>Barracuda\sNetworks\,\sInc\./ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string14 = /\>Barracuda\sRMM\sSetup\sAutoRun\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string15 = /\>Barracuda\sRMM\sSetup\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string16 = /\>Barracuda\sRMM.{0,100}\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string17 = /\>LPI\sLevel\sPlatforms\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string18 = /Barracuda\sRMM\sOnsite\sManager\s\-\sInstallShield\sWizard/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string19 = /Barracuda\sRMM\sOnsite\sManager\.msi/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string20 = /rmm\.barracudamsp\.com/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string21 = /whatsmyip\.ccrmm\.avg\.com/ nocase ascii wide
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
