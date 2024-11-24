rule commando_vm
{
    meta:
        description = "Detection patterns for the tool 'commando-vm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "commando-vm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string1 = /\.win10\.config\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string2 = /\.win7\.config\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string3 = "/commando-vm" nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string4 = /choco\sinstall\s.{0,100}\scommon\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string5 = /cmd\.cat\/chattr/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string6 = /commandovm\..{0,100}\.installer\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string7 = "commando-vm-master" nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string8 = /\-ExecutionPolicy\sBypass\s\-File\sWin10\.ps1\s/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string9 = /\-ExecutionPolicy\sBypass\s\-File\sWin11\.ps1\s/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string10 = /fireeye.{0,100}commando/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string11 = /https\:\/\/www\.myget\.org\/F\/fireeye\/api\/v2/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string12 = /Unblock\-File\s\.\\install\.ps1/ nocase ascii wide
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
