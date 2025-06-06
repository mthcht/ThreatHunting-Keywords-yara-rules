rule schtasks
{
    meta:
        description = "Detection patterns for the tool 'schtasks' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "schtasks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string1 = " /Create /RU SYSTEM /TN MicrosoftEdgeUpdateTaskMachine /TR " nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string2 = /\s\/create\s\/tn\s\\"SysChecks\\"\s\/tr\sc\:\\temp\\sch\.bat\s/ nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string3 = /\s\/Create\s\/TN\ssch\.bat\s\/TR\s\\"c\:\\temp\\script\.vbs\\"\s/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string4 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\ExploitGuard\\ExploitGuard\sMDM\spolicy\sRefresh\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string5 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sCache\sMaintenance\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string6 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sCleanup\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string7 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sScheduled\sScan\\"\s\/Disable/ nocase ascii wide
        // Description: disable scheduled tasks related to Windows Defender
        // Reference: https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/#c01
        $string8 = /schtasks\s\/Change\s\/TN\s\\"Microsoft\\Windows\\Windows\sDefender\\Windows\sDefender\sVerification\\"\s\/Disable/ nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string9 = /schtasks\s\/Create\s\/RU\sSYSTEM\s\/XML\sc\:\\temp\\/ nocase ascii wide
        // Description: view detailed information about all the scheduled tasks.
        // Reference: N/A
        $string10 = "schtasks /query /v /fo LIST" nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string11 = /schtasks\.exe\s\/create\s\/sc\s.{0,100}\s\/tr\s\\"\%programdata\%\\sshd\\sshd\.exe\s\-f\s\%programdata\%\\sshd\\config\\sshd_config\\keys\\id_rsa\s\-N\s\-R\s.{0,100}\s\-o\sStrictHostKeyChecking\=no\s\-o\s/ nocase ascii wide
        // Description: SSH backdoor creation with schtasks
        // Reference: https://www.trellix.com/blogs/research/cactus-ransomware-new-strain-in-the-market/
        $string12 = /schtasks\.exe\s\/create\s\/sc\sminute\s\/mo\s1\s\/tn\s.{0,100}\s\/rl\shighest\s\/np\s\/tr\s.{0,100}\\sshd\\sshd\.exe\s\-f\s.{0,100}\\sshd\\config\\sshd_config/ nocase ascii wide
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
