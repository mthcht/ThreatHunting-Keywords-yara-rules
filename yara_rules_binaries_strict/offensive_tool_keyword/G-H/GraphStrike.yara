rule GraphStrike
{
    meta:
        description = "Detection patterns for the tool 'GraphStrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GraphStrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string1 = /\sGraphStrike\.py/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string2 = /\.cobaltstrike\.beacon_keys/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string3 = /\/GraphStrike\.cna/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string4 = /\/GraphStrike\.git/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string5 = /\/graphstrike\.profile/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string6 = /\/GraphStrike\.py/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string7 = "/GraphStrike-main/" nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string8 = "/opt/cobaltstrike/" nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string9 = /\[\+\]\sRandomizing\ssyscall\snames/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string10 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string11 = /\\GraphLdr\.x64\.bin/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string12 = /\\GraphStrike\.cna/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string13 = /\\GraphStrike\.py/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string14 = /\\GraphStrike\-main\\/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string15 = /change_sandbox_evasion_method\(/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string16 = /GraphLdr\.x64\.bin/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string17 = /GraphLdr\.x64\.exe/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string18 = "GraphStrike Server is running and checking SharePoint for Beacon traffic" nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string19 = /GraphStrike\.py\s/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string20 = /Lost\sconnection\sto\steam\sserver\!\sSleeping\s60\ssecond\sand\sretrying\?/ nocase ascii wide
        // Description: Cobalt Strike HTTPS beaconing over Microsoft Graph API
        // Reference: https://github.com/RedSiege/GraphStrike
        $string21 = "RedSiege/GraphStrike" nocase ascii wide
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
