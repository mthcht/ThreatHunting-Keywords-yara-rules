rule _365_Stealer
{
    meta:
        description = "Detection patterns for the tool '365-Stealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "365-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string1 = " 365-Stealer " nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string2 = " --custom-steal" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string3 = " --custom-steal listusers" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string4 = " --custom-steal onedrive" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string5 = " --custom-steal onenote" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string6 = " --custom-steal outlook" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string7 = " Redirect Url After Stealing ==> " nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string8 = /\/365\-Stealer\.git/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string9 = /\[\!\]\sLooks\slike\sVictim\s.{0,1000}\sdoesn\'t\shave\soffice365\sLicence\!/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string10 = /\[\!\]\sStealing\sprocesses\sdelayed\swith\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string11 = /\[\!\]\sSwithed\sto\scustom\sstealing\.\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string12 = /\[\+\]\sVictim\s.{0,1000}\shave\soffice365\sLicence\!/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string13 = /365\-Stealer\.py/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string14 = "365-Stealer-master" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string15 = "AlteredSecurity/365-Stealer" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string16 = /cscript\s\.\.\\\\temp\.vbs/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string17 = "'Disable all http access logs'" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string18 = "'Host the Phising App'" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string19 = "MIIEowIBAAKCAQEAvZtOCbMyFKJN3n89nctTfYLSeiCTNG01rAFl06hMkobyzr0c" nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string20 = "o365-Attack-Toolkit" nocase ascii wide

    condition:
        any of them
}
