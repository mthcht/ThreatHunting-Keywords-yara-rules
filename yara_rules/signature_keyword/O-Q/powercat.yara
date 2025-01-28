rule powercat
{
    meta:
        description = "Detection patterns for the tool 'powercat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powercat"
        rule_category = "signature_keyword"

    strings:
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string1 = /PowerShell\/ReverseShell\.DR/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string2 = /Win\.Trojan\.Powercat\-/ nocase ascii wide

    condition:
        any of them
}
