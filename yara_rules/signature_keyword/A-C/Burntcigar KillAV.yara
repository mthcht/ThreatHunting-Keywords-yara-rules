rule Burntcigar_KillAV
{
    meta:
        description = "Detection patterns for the tool 'Burntcigar KillAV' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Burntcigar KillAV"
        rule_category = "signature_keyword"

    strings:
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string1 = /Trojan\.Win32\.KILLAV\.WLEAZ/ nocase ascii wide
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string2 = /Trojan\:Win32\/KillAV\.SA/ nocase ascii wide
        // Description: Scans for process names linked to known antivirus or EDR products - then adds their process IDs to a stack for later termination - often used by attackers
        // Reference: https://www.virustotal.com/gui/file/aeb044d310801d546d10b247164c78afde638a90b6ef2f04e1f40170e54dec03?nocache=1
        $string3 = "W32/CubaHR_KillAV" nocase ascii wide

    condition:
        any of them
}
