rule Box
{
    meta:
        description = "Detection patterns for the tool 'Box' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Box"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string1 = /\.realtime\.services\.box\.net/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string2 = /\/BoxDrive\.msi/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string3 = /\\\.boxcanvas\\BoxDesktop/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string4 = /\\box\.desktop\.updateservice\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string5 = /\\Box\.Updater\.Common\.dll/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string6 = /\\box\\box\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string7 = /\\Box\\ui\\BoxUI\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string8 = /\\BoxDesktop\.boxnote\\shell\\/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string9 = /\\BoxDrive\.msi/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string10 = /\\Program\sFiles\\Box\\Box\\/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string11 = /\\Root\\InventoryApplicationFile\\boxui\.exe/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string12 = /\>Box\,\sInc\.\</ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string13 = /Box\.Desktop\.Installer\.CustomActions/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string14 = /cdn.{0,100}\.boxcdn\.net/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string15 = /HKLM\\SOFTWARE\\Box\\Box/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string16 = /sanalytics\.box\.com/ nocase ascii wide
        // Description: Attackers have used box to store malicious files and then share them with targets - box can also be used for data exfiltration by attackers
        // Reference: https://app.box.com/
        $string17 = /upload\.box\.com/ nocase ascii wide
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
