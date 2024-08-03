rule Dameware
{
    meta:
        description = "Detection patterns for the tool 'Dameware' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dameware"
        rule_category = "signature_keyword"

    strings:
        // Description: Solarwind Dameware Mini Remote Control tool 
        // Reference: https://www.solarwinds.com/dameware-mini-remote-control
        $string1 = /RemoteAccess\:Win32\/DameWareMiniRemoteControl\.B/ nocase ascii wide

    condition:
        any of them
}
