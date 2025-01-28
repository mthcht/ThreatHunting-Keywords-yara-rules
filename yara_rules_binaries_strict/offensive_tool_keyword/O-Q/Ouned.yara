rule Ouned
{
    meta:
        description = "Detection patterns for the tool 'Ouned' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ouned"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string1 = /\saddcomputer_LDAP_spn\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string2 = /\saddcomputer_with_spns\.py\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string3 = /\s\-\-config\s.{0,100}\s\-\-just\-clean\s\-\-cleaning\-file\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string4 = /\souned_smbserver\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string5 = /\.py\s.{0,100}\s\-\-coerce\-to\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string6 = /\.py\s.{0,100}\s\-\-just\-coerce\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string7 = /\/addcomputer_LDAP_spn\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string8 = /\/addcomputer_with_spns\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string9 = /\/OUned\.git/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string10 = /\/ouned_smbserver\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string11 = /\[\+\]\sSuccessfully\sdownloaded\sGPO\sfrom\sfakedc\sto\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string12 = /\[\+\]\sSuccessfully\sinjected\smalicious\sscheduled\stask/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string13 = /\[\+\]\sSuccessfully\sspoofed\sgPLink\sfor\sOU\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string14 = /\[\+\]\sSuccessfully\supdated\sextension\snames\sof\sfakedc\sGPO/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string15 = /\[\+\]\sSuccessfully\suploaded\sGPO\sto\sSMB\sserver\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string16 = /\\\\\\\\\{attacker_ip\}\\\\/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string17 = /\\\\\\\\\{coerce_to\}\\\\/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string18 = /\\addcomputer_LDAP_spn\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string19 = /\\addcomputer_with_spns\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string20 = /\\ouned_smbserver\.py/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string21 = /\]\sCloning\sGPO\s.{0,100}\sfrom\sfakedc\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string22 = /\]\sInjecting\smalicious\sscheduled\stask\sinto\sdownloaded\sGPO/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string23 = /\]\sModifying\s.{0,100}\sattribute\sof\sGPO\son\sfakedc\sto\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string24 = /\]\sModifying\sgPCFileSysPath\sattribute\sof\sGPO\son\sfakedc\sto\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string25 = /\]\sSpoofing\sgPLink\sto\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string26 = "=== LAUNCHING SMB SERVER AND WAITING FOR GPT REQUESTS ===" nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string27 = "=== SPOOFING THE GPLINK ATTRIBUTE OF THE TARGET OU ===" nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string28 = /\=\=\=\sWAITING\s\(GPT\sREQUESTS\sWILL\sBE\sFORWARDED\sTO\sSMB\sSERVER\)\s\=\=\=/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string29 = /\=\=\=\sWAITING\s\(SMB\sNTLM\sAUTHENTICATION\sCOERCED\sTO\s/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string30 = "92bc6c12e5ead3c0c0069b53bcca9c2f21b9f2e10f1e4a05ef1efcd25bcc70e9" nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string31 = "99b685e2a57dbbdb0b53689aec5eef525a632c9ea00a5a16adb939387bf5a4da" nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string32 = "Could not write NTLM Hashes to the specified JTR_Dump_Path" nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string33 = /https\:\/\/www\.synacktiv\.com\/publications\/ounedpy\-exploiting\-hidden\-organizational\-units\-acl\-attack\-vectors\-in\-active\-directory/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string34 = "net user john H4x00r123" nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string35 = /Successfully\scloned\sGPO\s.{0,100}\sfrom\sSYSVOL/ nocase ascii wide
        // Description: The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning
        // Reference: https://github.com/synacktiv/Ouned
        $string36 = "synacktiv/OUned" nocase ascii wide
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
