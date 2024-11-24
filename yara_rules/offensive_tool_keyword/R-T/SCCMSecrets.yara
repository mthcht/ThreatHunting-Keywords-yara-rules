rule SCCMSecrets
{
    meta:
        description = "Detection patterns for the tool 'SCCMSecrets' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCCMSecrets"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SCCMSecrets.py aims at exploiting SCCM policies distribution for credentials harvesting - initial access and lateral movement.
        // Reference: https://github.com/synacktiv/SCCMSecrets
        $string1 = " --bruteforce-range " nocase ascii wide
        // Description: SCCMSecrets.py aims at exploiting SCCM policies distribution for credentials harvesting - initial access and lateral movement.
        // Reference: https://github.com/synacktiv/SCCMSecrets
        $string2 = /\/SCCMSecrets\.git/ nocase ascii wide
        // Description: SCCMSecrets.py aims at exploiting SCCM policies distribution for credentials harvesting - initial access and lateral movement.
        // Reference: https://github.com/synacktiv/SCCMSecrets
        $string3 = /bruteforcePackageIDs\(/ nocase ascii wide
        // Description: SCCMSecrets.py aims at exploiting SCCM policies distribution for credentials harvesting - initial access and lateral movement.
        // Reference: https://github.com/synacktiv/SCCMSecrets
        $string4 = "e3f71f6245226059b306c744af8038d045104c2a12aef8f6b6a254d963927e68" nocase ascii wide
        // Description: SCCMSecrets.py aims at exploiting SCCM policies distribution for credentials harvesting - initial access and lateral movement.
        // Reference: https://github.com/synacktiv/SCCMSecrets
        $string5 = /SCCMSecrets\.py/ nocase ascii wide
        // Description: SCCMSecrets.py aims at exploiting SCCM policies distribution for credentials harvesting - initial access and lateral movement.
        // Reference: https://github.com/synacktiv/SCCMSecrets
        $string6 = "synacktiv/SCCMSecrets" nocase ascii wide

    condition:
        any of them
}
