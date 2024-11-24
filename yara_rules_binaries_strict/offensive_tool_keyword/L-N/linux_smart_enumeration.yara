rule linux_smart_enumeration
{
    meta:
        description = "Detection patterns for the tool 'linux-smart-enumeration' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux-smart-enumeration"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string1 = /\s\$lse_find_opts\s/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string2 = /\.\/lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string3 = /\/etc\/passwd.{0,100}\/\.sudo_as_admin_successful/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string4 = /\/linux\-smart\-enumeration\.git/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string5 = /\/releases\/latest\/download\/lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string6 = /adm\|admin\|root\|sudo\|wheel/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string7 = /bash\slse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string8 = /chmod\s700\slse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string9 = /chmod\s755\slse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string10 = "diego-treitos/linux-smart-enumeration" nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string11 = /find\s\/\s.{0,100}\s\-4000\s\-type\sf\s\-print/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string12 = /find\s\/\s.{0,100}\s\-perm\s\-2000\s\-type\sf\s\-print/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string13 = /find\s\/\s.{0,100}\s\-regextype\segrep\s\-iregex.{0,100}\\\.kdbx/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string14 = /https\:\/\/.{0,100}\/releases\/download\/.{0,100}\/lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string15 = "linux-smart-enumeration-master" nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string16 = /lse\.sh\s\-l/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string17 = /netstat\s\-tnlp\s\|\|\sss\s\-tnlp/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string18 = /netstat\s\-unlp\s\|\|\sss\s\-unlp/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string19 = /package_cvs_into_lse\.sh/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string20 = /ss\s\-tunlp\s\|\|\snetstat\s\-tunlp.{0,100}127\.0\.0\.1/ nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string21 = "sudo -nS id' && lse_sudo=true" nocase ascii wide
        // Description: Linux enumeration tool for privilege escalation and discovery
        // Reference: https://github.com/diego-treitos/linux-smart-enumeration
        $string22 = /user\|username\|login\|pass\|password\|pw\|credentials/ nocase ascii wide
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
