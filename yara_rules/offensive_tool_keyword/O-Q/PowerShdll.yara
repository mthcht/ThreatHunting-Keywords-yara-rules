rule PowerShdll
{
    meta:
        description = "Detection patterns for the tool 'PowerShdll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShdll"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // Reference: https://github.com/p3nt4/PowerShdll
        $string1 = /36EBF9AA\-2F37\-4F1D\-A2F1\-F2A45DEEAF21/ nocase ascii wide
        // Description: Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // Reference: https://github.com/p3nt4/PowerShdll
        $string2 = /5067F916\-9971\-47D6\-BBCB\-85FB3982584F/ nocase ascii wide
        // Description: Run PowerShell with dlls only Does not require access to powershell.exe as it uses powershell automation dlls. PowerShdll can be run with: rundll32.exe. installutil.exe. regsvcs.exe. regasm.exe. regsvr32.exe or as a standalone executable.
        // Reference: https://github.com/p3nt4/PowerShdll
        $string3 = /PowerShdll/ nocase ascii wide

    condition:
        any of them
}
