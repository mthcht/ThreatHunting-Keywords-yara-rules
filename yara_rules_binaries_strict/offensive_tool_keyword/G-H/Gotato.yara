rule Gotato
{
    meta:
        description = "Detection patterns for the tool 'Gotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string1 = /\s\-p\s4644\s\-n\smal/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string2 = /\sProcess\sspawned\swith\sstolen\stoken\!/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string3 = /\/Gotato\.git/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string4 = /\/gotato\.go/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string5 = /\[\+\]\sStole\stoken\sfrom/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string6 = /\\\\\\\\\.\\\\pipe\\\\mal/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string7 = /gotato\s\-m\shttp/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string8 = /gotato\s\-m\spipe/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string9 = /gotato.{0,100}\s\-n\smal/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string10 = /gotato.{0,100}\s\-p\s4644/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string11 = /Gotato\-main\./ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string12 = /httpntlm\.go/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string13 = /httpntlm\.old/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string14 = /iammaguire\/Gotato/ nocase ascii wide
        // Description: Generic impersonation and privilege escalation with Golang. Like GenericPotato both named pipes and HTTP are supported.
        // Reference: https://github.com/iammaguire/Gotato
        $string15 = /TlRMTVNTUAACAAAABgAGADgAAAAFAomih5Y9EpIdLmMAAAAAAAAAAIAAgAA/ nocase ascii wide
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
