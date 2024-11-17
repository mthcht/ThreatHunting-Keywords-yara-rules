rule RunasCs
{
    meta:
        description = "Detection patterns for the tool 'RunasCs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RunasCs"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string1 = /\s\-\-remote\-impersonation/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string2 = /\sRunasCs\.cs/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string3 = /\s\-Username\s.{0,100}\s\-Password\s.{0,100}\s\-Command\s.{0,100}\s\-LogonType\s/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string4 = /\/RunasCs\.cs/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\/RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string6 = /\/RunasCs\.git/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string7 = /\/RunasCs\.git/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string8 = /\/RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string9 = /\\RunasCs\.cs/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string10 = /\\RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string11 = /antonioCoco\/RunasCs/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string12 = /antonioCoco\/RunasCs/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string13 = /base64_conversion_commands\.ps1/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string14 = /base64_conversion_commands\.ps1/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string15 = /\-\-bypass\-uac.{0,100}\-\-logontype/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string16 = /cmd\s\/c\s.{0,100}\s\-\-bypass\-uac/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string17 = /cmd\s\/c\s.{0,100}\s\-\-remote\-impersonation/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string18 = /Invoke\-RunasCs/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string19 = /Invoke\-RunasCs/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string20 = /Invoke\-RunasCs/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string21 = /\'Product\'\>RunasCs\</ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string22 = /RunasCreateProcessAsUserW/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string23 = /RunasCs\sv1\.5\s\-\s\@splinter_code/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string24 = /RunasCs.{0,100}\s\-\-remote\-impersonation/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string25 = /RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string26 = /RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string27 = /RunasCs_net2\.exe/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string28 = /RunasCs_net2\.exe/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string29 = /RunasCsMain/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string30 = /RunasCs\-master/ nocase ascii wide
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
