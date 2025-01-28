rule AnyplaceControl
{
    meta:
        description = "Detection patterns for the tool 'AnyplaceControl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AnyplaceControl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string1 = /\/anyplace\-control\/data2\/.{0,100}\.exe/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string2 = /\\Anyplace\sControl\s\-\sAdmin\.lnk/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string3 = /\\Anyplace\sControl\\/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string4 = /\\anyplace\-control\.ini/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string5 = /\\AppData\\Local\\Temp\\.{0,100}\\zmstage\.exe/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string6 = /\\AppData\\Roaming\\Anyplace\sControl/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string7 = /\\Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string8 = /\\ProgramData\\Anyplace\sControl\s/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string9 = ">Anyplace Control Software<" nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string10 = "a2fa034d006bdbc3ee2a15e55eb647f8097355c288a858da1e309fe8ac1cf0a3" nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string11 = /AnyplaceControlInstall\.exe/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string12 = /Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
        // Description: access your unattended PC from anywhere
        // Reference: www.anyplace-control[.]com
        $string13 = /www\.anyplace\-control\.com\/install/ nocase ascii wide
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
