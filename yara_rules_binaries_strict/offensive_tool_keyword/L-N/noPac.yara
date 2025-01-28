rule noPac
{
    meta:
        description = "Detection patterns for the tool 'noPac' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "noPac"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string1 = "/Ridter/noPac" nocase ascii wide
        // Description: command used in the method prerequisites of the POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string2 = /AdFind\.exe\s\-sc\sgetacls\s\-sddlfilter\s\s\s.{0,100}computer.{0,100}\s\s\-recmute/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string3 = /noPac\..{0,100}\s\-create\-child/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string4 = /noPac\..{0,100}\s\-dc\-host\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string5 = /noPac\..{0,100}\s\-dc\-ip\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string6 = /noPac\..{0,100}\s\-domain\-netbios/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string7 = /noPac\..{0,100}\s\-dump/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string8 = /noPac\..{0,100}\s\-hashes\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string9 = /noPac\..{0,100}\s\-\-impersonate\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string10 = /noPac\..{0,100}\s\-just\-dc\-ntlm/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string11 = /noPac\..{0,100}\s\-just\-dc\-user\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string12 = /noPac\..{0,100}\s\-new\-name\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string13 = /noPac\..{0,100}\s\-no\-add\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string14 = /noPac\..{0,100}\s\-pwd\-last\-set/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string15 = /noPac\..{0,100}\s\-service\-name\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string16 = /noPac\..{0,100}\s\-shell/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string17 = /noPac\..{0,100}\s\-shell\-type\s/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string18 = /noPac\..{0,100}\s\-use\-ldap/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string19 = /noPac\.py/ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string20 = /python\snoPac\./ nocase ascii wide
        // Description: POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string21 = "Ridter/noPac" nocase ascii wide
        // Description: script used in the POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string22 = /S4U2self\.py/ nocase ascii wide
        // Description: script used in the POC exploitation for CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
        // Reference: https://github.com/Ridter/noPac
        $string23 = /secretsdump\.py/ nocase ascii wide
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
