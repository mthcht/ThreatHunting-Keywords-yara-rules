rule mshta
{
    meta:
        description = "Detection patterns for the tool 'mshta' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mshta"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: using forfiles and mshta likely to evade detection and execute malicious code. It combines file enumeration with scripting and HTML-based execution which is commonly seen in malware or sophisticated attacks
        // Reference: N/A
        $string1 = /forfiles\.exe.{0,1000}\s\/p\s.{0,1000}\s\/m\s.{0,1000}\s\/c\s.{0,1000}powershell\s\.\smshta/ nocase ascii wide
        // Description: executing from public folder
        // Reference: N/A
        $string2 = /mshta\s\"C\:\\Users\\Public\\/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string3 = /mshta\shttp.{0,1000}\.hta/ nocase ascii wide
        // Description: downloading from tinyurl
        // Reference: N/A
        $string4 = /mshta\shttps\:\/\/tinyurl\.com\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string5 = /mshta\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
        // Description: Invoking a scriptlet file hosted remotely
        // Reference: N/A
        $string6 = /mshta\sjavascript\:a\=\(GetObject\(\"script\:http.{0,1000}\.sct.{0,1000}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string7 = /mshta\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide
        // Description: downloading from tinyurl
        // Reference: N/A
        $string8 = /mshta\.exe\shttps\:\/\/tinyurl\.com\// nocase ascii wide
        // Description: Invoking a scriptlet file hosted remotely
        // Reference: N/A
        $string9 = /mshta\.exe\sjavascript\:a\=\(GetObject\(\"script\:http.{0,1000}\.sct.{0,1000}\)\)\.Exec\(\)\;close\(\)\;/ nocase ascii wide
        // Description: executing from public folder
        // Reference: N/A
        $string10 = /mshta\.exe.{0,1000}\s\"C\:\\Users\\Public\\/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string11 = /mshta\.exe.{0,1000}\shttp\:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string12 = /mshta\.exe.{0,1000}\shttps\:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string13 = /mshta\.exe.{0,1000}\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string14 = /mshta\.exe.{0,1000}\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide

    condition:
        any of them
}
