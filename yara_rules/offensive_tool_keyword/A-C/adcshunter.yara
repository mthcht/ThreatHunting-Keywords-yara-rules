rule adcshunter
{
    meta:
        description = "Detection patterns for the tool 'adcshunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adcshunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Uses rpcdump to locate the ADCS server and identify if ESC8 is vulnerable from unauthenticated perspective.
        // Reference: https://github.com/danti1988/adcshunter
        $string1 = /\/adcshunter\.git/ nocase ascii wide
        // Description: Uses rpcdump to locate the ADCS server and identify if ESC8 is vulnerable from unauthenticated perspective.
        // Reference: https://github.com/danti1988/adcshunter
        $string2 = /ADCS\sServer\slocation\sidentified\son\sIP\s/ nocase ascii wide
        // Description: Uses rpcdump to locate the ADCS server and identify if ESC8 is vulnerable from unauthenticated perspective.
        // Reference: https://github.com/danti1988/adcshunter
        $string3 = /adcshunter\.py/ nocase ascii wide
        // Description: Uses rpcdump to locate the ADCS server and identify if ESC8 is vulnerable from unauthenticated perspective.
        // Reference: https://github.com/danti1988/adcshunter
        $string4 = /danti1988\/adcshunter/ nocase ascii wide
        // Description: Uses rpcdump to locate the ADCS server and identify if ESC8 is vulnerable from unauthenticated perspective.
        // Reference: https://github.com/danti1988/adcshunter
        $string5 = /impacket\-rpcdump/ nocase ascii wide
        // Description: Uses rpcdump to locate the ADCS server and identify if ESC8 is vulnerable from unauthenticated perspective.
        // Reference: https://github.com/danti1988/adcshunter
        $string6 = /rpcdump\.py/ nocase ascii wide
        // Description: Uses rpcdump to locate the ADCS server and identify if ESC8 is vulnerable from unauthenticated perspective.
        // Reference: https://github.com/danti1988/adcshunter
        $string7 = /Vulnerable\sWeb\sEnrollment\sendpoint\sidentified\:\shttp\:\/\/.{0,1000}\/certsrv\/certsnsh\.asp/ nocase ascii wide

    condition:
        any of them
}
