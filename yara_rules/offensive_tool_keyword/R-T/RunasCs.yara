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
        $string1 = /.{0,1000}\s\-\-remote\-impersonation.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string2 = /.{0,1000}\sRunasCs\.cs.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string3 = /.{0,1000}\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Command\s.{0,1000}\s\-LogonType\s.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string4 = /.{0,1000}\/RunasCs\.cs.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string5 = /.{0,1000}\/RunasCs\.git.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string6 = /.{0,1000}\/RunasCs\.git.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string7 = /.{0,1000}\/RunasCs\.zip.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string8 = /.{0,1000}\\RunasCs\.cs.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string9 = /.{0,1000}antonioCoco\/RunasCs.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string10 = /.{0,1000}antonioCoco\/RunasCs.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string11 = /.{0,1000}base64_conversion_commands\.ps1.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string12 = /.{0,1000}base64_conversion_commands\.ps1.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string13 = /.{0,1000}\-\-bypass\-uac.{0,1000}\-\-logontype.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string14 = /.{0,1000}cmd\s\/c\s.{0,1000}\s\-\-bypass\-uac.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string15 = /.{0,1000}cmd\s\/c\s.{0,1000}\s\-\-remote\-impersonation.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string16 = /.{0,1000}CreateProcessAsUser.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string17 = /.{0,1000}Invoke\-RunasCs.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string18 = /.{0,1000}Invoke\-RunasCs.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string19 = /.{0,1000}RunasCreateProcessAsUserW.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string20 = /.{0,1000}RunasCs\.exe.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string21 = /.{0,1000}RunasCs\.exe.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string22 = /.{0,1000}RunasCs\.zip.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string23 = /.{0,1000}RunasCs_net2\.exe.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string24 = /.{0,1000}RunasCs_net2\.exe.{0,1000}/ nocase ascii wide
        // Description: RunasCs is an utility to run specific processes with different permissions than the user's current logon provides using explicit credential
        // Reference: https://github.com/antonioCoco/RunasCs
        $string25 = /.{0,1000}RunasCsMain.{0,1000}/ nocase ascii wide
        // Description: RunasCs - Csharp and open version of windows builtin runas.exe
        // Reference: https://github.com/antonioCoco/RunasCs/
        $string26 = /.{0,1000}RunasCs\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
