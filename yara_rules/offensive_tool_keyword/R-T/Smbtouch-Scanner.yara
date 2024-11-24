rule Smbtouch_Scanner
{
    meta:
        description = "Detection patterns for the tool 'Smbtouch-Scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Smbtouch-Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string1 = "# Smbtouch Scanner" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string2 = /\/Smbtouch\-Scanner\.git/ nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string3 = "0259d41720f7084716a3b2bbe34ac6d3021224420f81a4e839b0b3401e5ef29f" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string4 = "0439628816cabe113315751e7113a9e9f720d7e499ffdd78acbac1ed8ba35887" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string5 = "108243f61c53f00f8f1adcf67c387a8833f1a2149f063dd9ef29205c90a3c30a" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string6 = "15292172a83f2e7f07114693ab92753ed32311dfba7d54fe36cc7229136874d9" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string7 = "2a222cd3c05cdbf6db8c226743bbb46ce9e384c1f59e39072d60910b1099b80c" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string8 = "3gstudent/Smbtouch-Scanner" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string9 = "aceb27720115a63b9d47e737fd878a61c52435ea4ec86ba8e58ee744bc85c4f3" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string10 = "b2a3172a1d676f00a62df376d8da805714553bb3221a8426f9823a8a5887daaa" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string11 = /C\:\\Windows\\system32\\cmd\.exe\s\/c\sC\:\\Windows\\Sysnative\\bcdedit\.exe\s1\>\sbcdedit\s2\>\&1/ nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string12 = "ca63dbb99d9da431bf23aca80dc787df67bb01104fb9358a7813ed2fce479362" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string13 = "cde45f7ff05f52b7215e4b0ea1f2f42ad9b42031e16a3be9772aa09e014bacdb" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string14 = "cf25bdc6711a72713d80a4a860df724a79042be210930dcbfc522da72b39bb12" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string15 = "f0df80978b3a563077def7ba919e2f49e5883d24176e6b3371a8eef1efe2b06a" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string16 = "fbe48841312643343af444c95bbc251c9e5dd6a40c784ea238ec9761e0886895" nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string17 = /Smbtouch\.exe/ nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string18 = /Smbtouch\-1\.1\.1\.exe/ nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string19 = /Smbtouch\-1\.1\.1\.xml/ nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string20 = /SmbtouchScanner\.py/ nocase ascii wide

    condition:
        any of them
}
