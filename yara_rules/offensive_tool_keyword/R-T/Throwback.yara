rule Throwback
{
    meta:
        description = "Detection patterns for the tool 'Throwback' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Throwback"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string1 = /\/Throwback\.git/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string2 = /\/ThrowbackDLL\// nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string3 = /\\Throwback\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string4 = /\\Throwback\\Throwback\.h/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string5 = /\\ThrowbackDLL\\/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string6 = /\\Throwback\-master\.zip/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string7 = /_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string8 = /60C1DA68\-85AC\-43AB\-9A2B\-27FA345EC113/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string9 = /D7D20588\-8C18\-4796\-B2A4\-386AECF14256/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string10 = /DLL_METASPLOIT_ATTACH/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string11 = /include\s\"ThrowbackDLL\.h\"/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string12 = /silentbreaksec\/Throwback/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string13 = /tbMangler\.py\sencode\s/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string14 = /Throwback\\Base64_RC4\.h/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string15 = /throwback_x64\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string16 = /throwback_x86\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string17 = /throwBackDev\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string18 = /ThrowbackDLL\.cpp/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string19 = /ThrowbackDLL\.exe/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string20 = /ThrowbackDLL\.vcxproj/ nocase ascii wide
        // Description: HTTP/S Beaconing Implant
        // Reference: https://github.com/silentbreaksec/Throwback
        $string21 = /ZAQwsxcde321/ nocase ascii wide

    condition:
        any of them
}
