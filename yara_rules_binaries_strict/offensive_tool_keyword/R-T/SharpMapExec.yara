rule SharpMapExec
{
    meta:
        description = "Detection patterns for the tool 'SharpMapExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMapExec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string1 = /\s\/m\:assembly\s\/p\:beacon\.exe/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string2 = /\s\/m\:assembly\s\/p\:getMailBox\.exe/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string3 = /\(Get\-Process\slsass\)\.Id/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string4 = /\.exe\skerberos\sldap\s.{0,100}\s\/m\:spraydata/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string5 = /\.exe\skerberos\sldap\s.{0,100}\s\/password\:.{0,100}\s\/dc\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string6 = /\.exe\skerberos\sldap\s.{0,100}\s\/ticket\:.{0,100}\s\/m\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string7 = /\.exe\skerberos\sreg32\s.{0,100}\s\/m\:check_pslockdown/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string8 = /\.exe\skerberos\sreg32\s.{0,100}\s\/m\:check_pslogging/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string9 = /\.exe\skerberos\sreg32\s.{0,100}\s\/m\:disable_pslockdown/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string10 = /\.exe\skerberos\sreg32\s.{0,100}\s\/password\:.{0,100}\s\/dc\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string11 = /\.exe\skerberos\sreg32\s.{0,100}\s\/ticket\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string12 = /\.exe\skerberos\ssmb\s.{0,100}\s\/computername\:.{0,100}\s\/ticket\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string13 = /\.exe\skerberos\ssmb\s.{0,100}\s\/m\:shares/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string14 = /\.exe\skerberos\ssmb\s.{0,100}\s\/password\:.{0,100}\s\/dc\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string15 = /\.exe\skerberos\ssmb\s.{0,100}\s\/ticket\:.{0,100}\s\/computername\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string16 = /\.exe\skerberos\swinrm\s.{0,100}\s\/computername\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string17 = /\.exe\skerberos\swinrm\s.{0,100}\s\/m\:assembly\s\/p\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string18 = /\.exe\skerberos\swinrm\s.{0,100}\s\/m\:comsvcs/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string19 = /\.exe\skerberos\swinrm\s.{0,100}\s\/m\:download\s/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string20 = /\.exe\skerberos\swinrm\s.{0,100}\s\/m\:exec\s\/a\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string21 = /\.exe\skerberos\swinrm\s.{0,100}\s\/m\:secrets/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string22 = /\.exe\skerberos\swinrm\s.{0,100}\s\/m\:upload/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string23 = /\.exe\skerberos\swinrm\s.{0,100}\s\/rc4\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string24 = /\.exe\skerbspray\s/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string25 = /\.exe\sntlm\scim\s.{0,100}\s\/m\:check_pslockdown/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string26 = /\.exe\sntlm\scim\s.{0,100}\s\/m\:check_pslogging/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string27 = /\.exe\sntlm\scim\s.{0,100}\s\/m\:disable_pslockdown/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string28 = /\.exe\sntlm\scim\s.{0,100}\s\/m\:disable_pslogging/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string29 = /\.exe\sntlm\scim\s.{0,100}\s\/m\:disable_winrm/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string30 = /\.exe\sntlm\scim\s.{0,100}\s\/m\:enable_winrm/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string31 = /\.exe\sntlm\scim\s.{0,100}\s\/user\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string32 = /\.exe\sntlm\sldap\s.{0,100}\s\/m\:spraydata/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string33 = /\.exe\sntlm\sldap\s.{0,100}\s\/password\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string34 = /\.exe\sntlm\sreg32\s.{0,100}\s\/m\:check_pslockdown/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string35 = /\.exe\sntlm\sreg32\s.{0,100}\s\/m\:check_pslogging/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string36 = /\.exe\sntlm\sreg32\s.{0,100}\s\/m\:disable_pslockdown/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string37 = /\.exe\sntlm\sreg32\s.{0,100}\s\/ntlm\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string38 = /\.exe\sntlm\ssmb\s.{0,100}\s\/m\:shares/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string39 = /\.exe\sntlm\ssmb\s.{0,100}\s\/ntlm\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string40 = /\.exe\sntlm\swinrm\s.{0,100}\s\/m\:assembly\s\/p\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string41 = /\.exe\sntlm\swinrm\s.{0,100}\s\/m\:comsvcs/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string42 = /\.exe\sntlm\swinrm\s.{0,100}\s\/m\:download/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string43 = /\.exe\sntlm\swinrm\s.{0,100}\s\/m\:exec\s\/a\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string44 = /\.exe\sntlm\swinrm\s.{0,100}\s\/m\:secrets/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string45 = /\.exe\sntlm\swinrm\s.{0,100}\s\/m\:upload/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string46 = /\.exe\sntlm\swinrm\s.{0,100}\s\/password\:/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string47 = /\.exe\stgtdeleg/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string48 = /\/SharpMapExec\.exe/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string49 = /\/SharpMapExec\.git/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string50 = /\\SharpMapExec\.exe/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string51 = /\\SharpMapExec\.sln/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string52 = /\\SharpMapExec\\/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string53 = /\]\sCopying\slsass\sdump/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string54 = ">SharpMapExec<" nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string55 = "b32521b722e44343d730559adf79326d2f4e3126417d934319ab4088185e0f7b" nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string56 = /base64\(ticket\.kirbi/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string57 = "BD5220F7-E1FB-41D2-91EC-E4C50C6E9B9F" nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string58 = /C\:\\\\windows\\\\temp\\\\Coredump\.dmp/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string59 = /C\:\\\\windows\\\\temp\\\\sam/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string60 = /C\:\\windows\\temp\\Coredump\.dmp/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string61 = "cube0x0/SharpMapExec" nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string62 = "f85996adb68f4d1c09f87c896a686530cc08df05aeaaa885756bf4508470ceaf" nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string63 = "full; Wait-Process rundll32" nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string64 = /SharpMapExec\-main\.zip/ nocase ascii wide
        // Description: A sharpen version of CrackMapExec
        // Reference: https://github.com/cube0x0/SharpMapExec
        $string65 = "Using a domain DPAPI backup key to triage masterkeys for decryption key mappings" nocase ascii wide
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
