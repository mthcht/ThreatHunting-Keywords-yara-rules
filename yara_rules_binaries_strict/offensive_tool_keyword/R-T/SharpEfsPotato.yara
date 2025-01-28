rule SharpEfsPotato
{
    meta:
        description = "Detection patterns for the tool 'SharpEfsPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEfsPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string1 = /\sC\:\\temp\\w\.log/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string2 = " SharpEfsPotato" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string3 = "/SharpEfsPotato" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string6 = /\\SharpEfsPotato/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string7 = /\\SharpEfsPotato\.pdb/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string8 = ">SharpEfsPotato<" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string9 = "AAB4D641-C310-4572-A9C2-6D12593AB28E" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string10 = "SharpEfsPotato by @bugch3ck" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string11 = "SharpEfsPotato by @bugch3ck" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string12 = /SharpEfsPotato\.cs/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string13 = /SharpEfsPotato\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string14 = /SharpEfsPotato\.exe/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string15 = /SharpEfsPotato\.sln/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string16 = "SharpEfsPotato-master" nocase ascii wide
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
