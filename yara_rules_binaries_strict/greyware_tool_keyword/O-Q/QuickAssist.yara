rule QuickAssist
{
    meta:
        description = "Detection patterns for the tool 'QuickAssist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "QuickAssist"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string1 = /\s\-\-webview\-exe\-name\=QuickAssist\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string2 = /\/Assistance\srapide\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string3 = /\/Assistenza\srapida\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string4 = /\/Quick\sAssist\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string5 = /\/Quick\%20Assist\%20Installer\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string6 = /\\AppData\\Local\\Temp\\RemoteHelp\\EBWebView/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string7 = /\\Assistance\srapide\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string8 = /\\Assistenza\srapida\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string9 = /\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\.{0,100}\\MicrosoftCorporationII\.QuickAssist_/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string10 = /\\Microsoft\.RemoteAssistance\.QuickAssist\\/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string11 = /\\microsoft\.remoteassistance\.quickassist\\/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string12 = /\\Quick\sAssist\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string13 = /\\QuickAssist\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string14 = /\\QuickAssist\.pdb/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string15 = /\\SOFTWARE\\Microsoft\\Tracing\\Quick\sAssist\sInstaller/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string16 = /\\WindowsApps\\MicrosoftCorporationII\.QuickAssist_/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string17 = /\\WinSxS\\amd64_microsoft\-windows\-quickassist_/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string18 = "<Provider Name='Quick Assist'/>" nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string19 = ">Quick Assist Component<" nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string20 = /Assistencia\sRapida\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string21 = /Command\:\sbeginsharing\sResult\:\s\{\\"responsename\\"\:\\"beginsharing\\"/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string22 = /contactsupportrelays4\-prod\.eastus\.cloudapp\.azure\.com/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string23 = /https\:\/\/rdprelay.{0,100}\.support\.services\.microsoft\.com/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string24 = /https\:\/\/remoteassistance\.support\.services\.microsoft\.com\// nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string25 = /Incoming\scmd\sMessage\:\s\{\\"command\\"\:\\"beginsharing\\"/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string26 = /Info\:\s\{\\"command\\"\:\\"forwardtoagent\\"\,\s\\"context\\"\:\{\\"command\\"\:\\"requestresponse\\"\,\\"context\\"\:\{\\"responsename\\"\:\\"beginsharing/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string27 = /Info\:\s\{\\"command\\"\:\\"rdp_native_event\\"\,\s\\"context\\"\:\{\s\\"eventname\\"\:\\"rdp_native_relay_connection_succeeded\\"\}\s/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string28 = /QuickAssist\.exe\slaunched/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string29 = /SOFTWARE\\Microsoft\\QuickAssist/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string30 = /Szybka\spomoc\sInstaller\.exe/ nocase ascii wide
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
