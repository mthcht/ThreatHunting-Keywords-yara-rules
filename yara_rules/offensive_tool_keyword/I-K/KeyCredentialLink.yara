rule KeyCredentialLink
{
    meta:
        description = "Detection patterns for the tool 'KeyCredentialLink' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeyCredentialLink"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string1 = /\s\/domain\:.{0,1000}\s\/dc\:.{0,1000}\s\/getcredentials\s\/nowrap/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string2 = /\sKeyCredentialLink\.ps1/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string3 = /\.exe\sasktgt\s\/user\:.{0,1000}\s\/certificate\:.{0,1000}\s\/password\:/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string4 = /\/KeyCredentialLink\.git/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string5 = /\/KeyCredentialLink\.ps1/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string6 = /\\KeyCredentialLink\.ps1/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string7 = /\\Public\\Documents\\DSInternals/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string8 = /1257077a68f9725d863947e0931a44727fceaad6565b73b9f8d873cc3d028e00/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string9 = /5db4c8112942c658a4f14d16fff13781dd705273c0050b2ada09ec79c7cb7c87/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string10 = /Add\-KeyCredentials\s\-target\s/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string11 = /AERTSW50ZXJuYWxzXHg4Nlx2Y3J1bnRpbWUxNDBfdGhyZWFkcy5kbGxQSwECFAAUAAAACAAnnY1YrbP4grERAAA9RQAADwAAAAAAAAAAAAAAAABk7yEARFNJbnRlcm5hbHMuY2F0UEsFBgAAAAAwADAAdRAAAEIBIgAAAA\=\=/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string12 = /Clear\-KeyCredentials\s\-target\s/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string13 = /Leo4j\/KeyCredentialLink/ nocase ascii wide
        // Description: Add Shadow Credentials to a target object by editing their msDS-KeyCredentialLink attribute
        // Reference: https://github.com/Leo4j/KeyCredentialLink
        $string14 = /List\-KeyCredentials\s\-target\s/ nocase ascii wide

    condition:
        any of them
}
