rule Invoke_CleverSpray
{
    meta:
        description = "Detection patterns for the tool 'Invoke-CleverSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-CleverSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string1 = /\$AllCurrentPwdDiscovered/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string2 = /\$TotalNbCurrentPwdDiscovered/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string3 = /\/Invoke\-CleverSpray\.git/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string4 = /\[\!\]\sPassword\sspraying\swill\sbe\sconducted/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string5 = /\[\!\]\sThe\spassword\s.{0,1000}\swill\sbe\ssprayed\son\stargeted\suser\saccounts\shaving/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string6 = /fdb1df0047a31328f0796bd07caf642efc35651ad78389025eb5afa2748bcd04/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string7 = /Invoke\-CleverSpray/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string8 = /Invoke\-CleverSpray\.ps1/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string9 = /Please\suse\sthe\s\-Password\soption\sto\sspecify\sa\sunique\spassword\sto\sspray/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string10 = /Please\suse\sthe\s\-User\soption\sto\sspecify\sa\sunique\susername\sto\sspray/ nocase ascii wide
        // Description: Password Spraying Script detecting current and previous passwords of Active Directory User
        // Reference: https://github.com/wavestone-cdt/Invoke-CleverSpray
        $string11 = /wavestone\-cdt\/Invoke\-CleverSpray/ nocase ascii wide

    condition:
        any of them
}
