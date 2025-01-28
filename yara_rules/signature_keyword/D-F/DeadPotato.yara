rule DeadPotato
{
    meta:
        description = "Detection patterns for the tool 'DeadPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DeadPotato"
        rule_category = "signature_keyword"

    strings:
        // Description: DeadPotato is a windows privilege escalation utility from the Potato family of exploits leveraging the SeImpersonate right to obtain SYSTEM privileges
        // Reference: https://github.com/lypd0/DeadPotato
        $string1 = "Trojan:MSIL/GodPotato" nocase ascii wide

    condition:
        any of them
}
