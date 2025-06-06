rule PWDumpX
{
    meta:
        description = "Detection patterns for the tool 'PWDumpX' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWDumpX"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string1 = /\sDumpSvc\.exe/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string2 = " PWDumpX process " nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string3 = " PWDumpX service " nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string4 = /\/DumpSvc\.exe/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string5 = /\\DumpExt\.dll/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string6 = /\\DumpSvc\.exe/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string7 = /\\LSASecrets\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string8 = /\\PWDumpX\.c/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string9 = /\\PWHashes\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string10 = /\\services\\PWDumpX\\/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string11 = "_DumpLSASecrets" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string12 = ">PWDumpX Service<" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string13 = "12e55226b801ebdfcc9334ca438a57db1da463de48e2893009a7bb3e5e5e0dbc" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string14 = "3f5ea2764696b07fdb61c7b34736eae26518ed2e36a624df09fb37025659201f" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string15 = "3f5ea2764696b07fdb61c7b34736eae26518ed2e36a624df09fb37025659201f" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string16 = "52b9c0a0a0188e47cb4b812aabe5a1832633fe9d66cebf702dfe0de114db0abd" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string17 = "5c85b965c19ff7f7742980f90965279aa0ae2ea4c50317ad7680b56d6e3ed9d5" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string18 = "78b4ff5e1bbac4a8bde265705a5c6e36b41bb2a9170f8f060a09bb1552549af2" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string19 = "79c1d4ab8f425095d2d9f2a18a0cab08d31b686b149fba3db24a13e2bc7299ee" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string20 = "80a9520b464f4bd7b4747c897a66a3c41a9100cb9efcd94614e2bd053247285a" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string21 = "Cannot enable SE_DEBUG_NAME privilege on remote host" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string22 = "Cannot get LSASS PID on remote host" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string23 = "Cannot load SAM functions on remote host" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string24 = "Cannot open LSA policy on remote host" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string25 = /Cannot\sopen\sregistry\skey\sHKLM\\SECURITY\\Policy\\Secrets\son\sremote\shost/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string26 = "Cannot open SAM on remote host" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string27 = /https\:\/\/reedarvin\.thearvins\.com\// nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string28 = "-LIBGCCW32-EH-3-SJLJ-GTHR-MINGW32" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string29 = /\-LSASecrets\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string30 = "PWDumpDLLPath" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string31 = "PWDumpEXEPath" nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string32 = "PWDumpX " nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string33 = /PWDumpX\sv1\.0/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string34 = /PWDumpX\.zip/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string35 = /\-PWHashes\.txt/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string36 = /reedarvin\@gmail\.com/ nocase ascii wide
        // Description: PWDumpX tool allows a user with administrative privileges to retrieve the encrypted password hashes and LSA secrets from a Windows system. This tool can be used on the local system or on one or more remote systems.
        // Reference: https://packetstormsecurity.com/files/download/52580/PWDumpX.zip
        $string37 = "szRemotePWDumpEXEPath" nocase ascii wide
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
