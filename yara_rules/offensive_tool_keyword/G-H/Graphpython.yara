rule Graphpython
{
    meta:
        description = "Detection patterns for the tool 'Graphpython' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Graphpython"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string1 = /\sbackdoored\-script\.ps1/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string2 = /\sGraphpython\.py/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string3 = /\sKillchain\.ps1/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string4 = /\/backdoored\-script\.ps1/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string5 = /\/Graphpython\.git/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string6 = /\/Graphpython\.py/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string7 = /\/Killchain\.ps1/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string8 = /\\backdoored\-script\.ps1/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string9 = /\\Graphpython\.py/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string10 = /\\Killchain\.ps1/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string11 = "38707a769a7eb4bd3e4165eaa94d727b33e7a83d974464c5f6a4fb9d6ef7d43f" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string12 = "6f3c6aacdcbeacc32a31e6ad49ac47e3f9d315ef277fe75125f7e596b592310e" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string13 = "9dab89ef77aae50a68e256bf169057ea3083869c80a3caddccbddecc5b4f61f7" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string14 = "--command assign-privilegedrole --token " nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string15 = "--command backdoor-script --id " nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string16 = "--command deploy-maliciousscript --script " nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string17 = "--command invoke-reconasoutsider --domain " nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string18 = "--command invoke-userenumerationasoutsider --username " nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string19 = "--command spoof-owaemailmessage " nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string20 = /dump_owamailbox\(/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string21 = /Graphpython\.__main__/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string22 = /Graphpython\.utils\.helpers/ nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string23 = "Invoke-AADIntReconAsGuest" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string24 = "Invoke-AADIntUserEnumerationAsGuest" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string25 = "Invoke-ESTSCookieToAccessToken" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string26 = "Invoke-MFASweep" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string27 = "Invoke-UserEnumerationAsOutsider" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string28 = "mlcsec/Graphpython" nocase ascii wide
        // Description: Modular cross-platform Microsoft Graph API (Entra - o365 and Intune) enumeration and exploitation toolkit
        // Reference: https://github.com/mlcsec/Graphpython
        $string29 = /mlcsec\@proton\.me/ nocase ascii wide

    condition:
        any of them
}
