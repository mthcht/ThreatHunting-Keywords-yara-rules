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
        $string9 = /\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\.{0,1000}\\MicrosoftCorporationII\.QuickAssist_/ nocase ascii wide
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
        $string18 = /\<Provider\sName\=\'Quick\sAssist\'\/\>/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string19 = /\>Quick\sAssist\sComponent\</ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string20 = /Assistencia\sRapida\sInstaller\.exe/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string21 = /Command\:\sbeginsharing\sResult\:\s\{\"responsename\"\:\"beginsharing\"/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string22 = /contactsupportrelays4\-prod\.eastus\.cloudapp\.azure\.com/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string23 = /https\:\/\/rdprelay.{0,1000}\.support\.services\.microsoft\.com/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string24 = /https\:\/\/remoteassistance\.support\.services\.microsoft\.com\// nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string25 = /Incoming\scmd\sMessage\:\s\{\"command\"\:\"beginsharing\"/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string26 = /Info\:\s\{\"command\"\:\"forwardtoagent\"\,\s\"context\"\:\{\"command\"\:\"requestresponse\"\,\"context\"\:\{\"responsename\"\:\"beginsharing/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string27 = /Info\:\s\{\"command\"\:\"rdp_native_event\"\,\s\"context\"\:\{\s\"eventname\"\:\"rdp_native_relay_connection_succeeded\"\}\s/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string28 = /QuickAssist\.exe\slaunched/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string29 = /SOFTWARE\\Microsoft\\QuickAssist/ nocase ascii wide
        // Description: Sharing remote desktop with Microsoft Quick assit
        // Reference: https://apps.microsoft.com/detail/9p7bp5vnwkx5
        $string30 = /Szybka\spomoc\sInstaller\.exe/ nocase ascii wide

    condition:
        any of them
}
