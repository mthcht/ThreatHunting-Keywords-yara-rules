rule VNCPassView
{
    meta:
        description = "Detection patterns for the tool 'VNCPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VNCPassView"
        rule_category = "signature_keyword"

    strings:
        // Description: recover the passwords stored by the VNC tool
        // Reference: https://www.nirsoft.net/utils/vnc_password.html
        $string1 = "HackTool:Win32/Passview!MSR" nocase ascii wide
        // Description: recover the passwords stored by the VNC tool
        // Reference: https://www.nirsoft.net/utils/vnc_password.html
        $string2 = /VNCPassView\.exe/ nocase ascii wide

    condition:
        any of them
}
