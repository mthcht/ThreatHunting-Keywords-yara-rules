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
        $string3 = /\s\-Username\s.*\s\-Password\s.*\s\-Command\s.*\s\-LogonType\s/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string4 = /\/RunasCs\.cs/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string5 = /\/RunasCs\.git/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string6 = /\/RunasCs\.git/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string7 = /\/RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string8 = /\\RunasCs\.cs/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string9 = /antonioCoco\/RunasCs/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string10 = /antonioCoco\/RunasCs/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string11 = /base64_conversion_commands\.ps1/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string12 = /base64_conversion_commands\.ps1/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string13 = /\-\-bypass\-uac.*\-\-logontype/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string14 = /cmd\s\/c\s.*\s\-\-bypass\-uac/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string15 = /cmd\s\/c\s.*\s\-\-remote\-impersonation/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string16 = /CreateProcessAsUser/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string17 = /Invoke\-RunasCs/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string18 = /Invoke\-RunasCs/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string19 = /RunasCreateProcessAsUserW/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string20 = /RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string21 = /RunasCs\.exe/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string22 = /RunasCs\.zip/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string23 = /RunasCs_net2\.exe/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string24 = /RunasCs_net2\.exe/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string25 = /RunasCsMain/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string26 = /RunasCs\-master/ nocase ascii wide

    condition:
        any of them
}