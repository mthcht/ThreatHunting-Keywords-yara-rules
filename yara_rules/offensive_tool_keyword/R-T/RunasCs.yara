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
        $string1 = " --remote-impersonation" nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string2 = /\sRunasCs\.cs/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string3 = /\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Command\s.{0,1000}\s\-LogonType\s/ nocase ascii wide
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
        $string11 = "antonioCoco/RunasCs" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string12 = "antonioCoco/RunasCs" nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string13 = /base64_conversion_commands\.ps1/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string14 = /base64_conversion_commands\.ps1/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string15 = /\-\-bypass\-uac.{0,1000}\-\-logontype/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string16 = /cmd\s\/c\s.{0,1000}\s\-\-bypass\-uac/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string17 = /cmd\s\/c\s.{0,1000}\s\-\-remote\-impersonation/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string18 = "Invoke-RunasCs" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string19 = "Invoke-RunasCs" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string20 = "Invoke-RunasCs" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string21 = "'Product'>RunasCs<" nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string22 = "RunasCreateProcessAsUserW" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string23 = /RunasCs\sv1\.5\s\-\s\@splinter_code/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string24 = /RunasCs.{0,1000}\s\-\-remote\-impersonation/ nocase ascii wide
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
        $string29 = "RunasCsMain" nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string30 = "RunasCs-master" nocase ascii wide

    condition:
        any of them
}
