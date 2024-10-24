rule sshdoor
{
    meta:
        description = "Detection patterns for the tool 'sshdoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshdoor"
        rule_category = "signature_keyword"

    strings:
        // Description: Openssh backdoor
        // Reference: https://web-assets.esetstatic.com/wls/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf
        $string1 = /Backdoor\.Linux\.Spyssh\.J/ nocase ascii wide
        // Description: Openssh backdoor
        // Reference: https://web-assets.esetstatic.com/wls/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf
        $string2 = /Backdoor\.Linux\.Sshdkit/ nocase ascii wide
        // Description: Openssh backdoor
        // Reference: https://web-assets.esetstatic.com/wls/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf
        $string3 = /Linux\/SSHDoor/ nocase ascii wide
        // Description: Openssh backdoor
        // Reference: https://web-assets.esetstatic.com/wls/2018/12/ESET-The_Dark_Side_of_the_ForSSHe.pdf
        $string4 = /Trojan\.Linux\.SSHDoor/ nocase ascii wide

    condition:
        any of them
}
