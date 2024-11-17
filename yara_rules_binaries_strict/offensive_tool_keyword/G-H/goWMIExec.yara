rule goWMIExec
{
    meta:
        description = "Detection patterns for the tool 'goWMIExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goWMIExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string1 = /\sgoWMIExec_linux_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string2 = /\sgoWMIExec_mac_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string3 = /\sgoWMIExec_win_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string4 = /\/goWMIExec\.git/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string5 = /\/goWMIExec_linux_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string6 = /\/goWMIExec_mac_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string7 = /\/goWMIExec_win_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string8 = /\\goWMIExec_linux_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string9 = /\\goWMIExec_mac_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string10 = /\\goWMIExec_win_/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string11 = /0e5ae252e2597d44f6e8def9fcdd3562954130a0261776e083959d067795c450/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string12 = /5c5dc6546877d616c4479df133654a0fbccc71d5279aa63f2ca560a5abfea31d/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string13 = /5cdce3c908a8a7a336d21543c1133071b6395e26ca882cafc05fb6dbdce075f1/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string14 = /C\-Sto\/goWMIExec/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string15 = /ef881142422dd10c7ad27424ce2407312b3886c5ee940a4be17153caed6ccaff/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string16 = /goWMIExec\s\-target\s/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string17 = /goWMIExec\/pkg/ nocase ascii wide
        // Description: re-implementation of invoke-wmiexec (Lateral Movement)
        // Reference: https://github.com/C-Sto/goWMIExec
        $string18 = /wmiexec\\wmiexec\.go/ nocase ascii wide
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
