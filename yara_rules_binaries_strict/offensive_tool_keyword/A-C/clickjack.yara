rule clickjack
{
    meta:
        description = "Detection patterns for the tool 'clickjack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "clickjack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\s\-\-CollectLinks\s\-\-apitoken\s.{0,100}\s\-\-outfile\s/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\s\-\-Inject\s\-\-stub\s.{0,100}\.dll.{0,100}\s\-\-app\s/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\/ClickJack\.exe/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\[\!\]\sThis\sapplication\scan\snot\sbe\sinjected/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\[\+\]\sThis\sapplication\sis\sinjectable\!/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\\ClickJack\.csproj/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\\ClickJack\.exe/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = "02FAF312-BF2A-466B-8AD2-1339A31C303B" nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = "40e8b756d0f996d7127ffc76d3fb122dd014455bc6b0c007e6d5d77e5bb6211b" nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = "88f333f2f21ca05e44a91c376022997c2bbec79b9d9982d59ee6d38183df86f3" nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /InjectApp\.InfectClickonceApp\(/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /using\sClickJack\.Extensions/ nocase ascii wide
        // Description: automate abuse of clickonce applications
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /using\sClickJack\.Modules/ nocase ascii wide
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
