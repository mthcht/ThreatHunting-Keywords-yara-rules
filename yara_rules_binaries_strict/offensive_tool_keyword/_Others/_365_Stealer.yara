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
        $string9 = /\[\!\]\sLooks\slike\sVictim\s.{0,100}\sdoesn\'t\shave\soffice365\sLicence\!/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string10 = /\[\!\]\sStealing\sprocesses\sdelayed\swith\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string11 = /\[\!\]\sSwithed\sto\scustom\sstealing\.\s/ nocase ascii wide
        // Description: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack
        // Reference: https://github.com/AlteredSecurity/365-Stealer
        $string12 = /\[\+\]\sVictim\s.{0,100}\shave\soffice365\sLicence\!/ nocase ascii wide
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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
