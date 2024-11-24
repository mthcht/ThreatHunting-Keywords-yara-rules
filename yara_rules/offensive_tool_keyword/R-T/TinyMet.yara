rule TinyMet
{
    meta:
        description = "Detection patterns for the tool 'TinyMet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TinyMet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string1 = /\/tinymet\.exe/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string2 = /\\tinymet\.exe/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string3 = /0_evil\.com_4444\.exe/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string4 = "331952cdf2781133eafa25e3115db3e9cfb2cbf9b208fbcb6a462eab2e314343" nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string5 = "3e8b305a4b6157e6f3ed492c596cfda37d27bf63e1532516aa96ec10eed3d166" nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string6 = "DA06A931-7DCA-4149-853D-641B8FAA1AB9" nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string7 = /TinyMet\sv0\.2\\ntinymet\.com/ nocase ascii wide
        // Description: meterpreter stager
        // Reference: https://github.com/SherifEldeeb/TinyMet
        $string8 = /www\.tinymet\.com/ nocase ascii wide

    condition:
        any of them
}
