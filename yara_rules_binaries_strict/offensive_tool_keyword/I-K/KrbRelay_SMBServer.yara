rule KrbRelay_SMBServer
{
    meta:
        description = "Detection patterns for the tool 'KrbRelay-SMBServer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrbRelay-SMBServer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string1 = /\s\-endpoint\s.{0,100}\s\-adcs\s.{0,100}\s\-listenerport\s/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string2 = /\sKrbRelay\.HiveParser/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string3 = /\ssmb_control\.bat/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string4 = /\.exe\s\-spn\s.{0,100}\s\-redirecthost\s/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string5 = /\/DFSCoerce\.exe/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string6 = /\/KrbRelay\.exe/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string7 = /\/KrbRelay\-SMBServer\.git/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string8 = "/KrbRelay-SMBServer/releases/" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string9 = /\\DFSCoerce\.exe/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string10 = /\\KrbRelay\.exe/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string11 = /\\KrbRelay\-SMBServer\.sln/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string12 = /\\smb_control\.bat/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string13 = /\\windows\\temp\\sam\.tmp/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string14 = /\\windows\\temp\\sec\.tmp/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string15 = /\\windows\\temp\\sys\.tmp/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string16 = /\]\sStopping\sLLMNR\sspoofing\\"/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string17 = "1be9af3e46ecda17aed9e3c5c563003b5f1fd31b9833fd85e69e11fb53a6bc4d" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string18 = "3b0c09c1852353c15372d27a6c0971472ef165c093024073990446219a887034" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string19 = "3B47EEBC-0D33-4E0B-BAB5-782D2D3680AF" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string20 = "44e769288f34ec5abca4d42a2ff890bf7e9f00218abce392076682226a74de45" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string21 = "577b289bf6f2a7353f4fb0f6a8a84103f6583710a08d8ff1e1fb817b45cccaa4" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string22 = "dcbe3cad78afb24101b169bebec5b6d607a567c661fc3e39a659d260789699b4" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string23 = "decoder-it/KrbRelay-SMBServer" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string24 = "ED839154-90D8-49DB-8CDD-972D1A6B2CFD" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string25 = "f4830ceea028f835f721ec2f9c84ba6d23f516be5f02aa6f53d60611fb730925" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string26 = "f9ef944aa1980e6ed8153cb2c8926559203d9aa6e1db388efbeabb705d9fe57f" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string27 = "invoke-dnsupdate " nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string28 = "KrbRelay by @Cube0x0" nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string29 = /Rubeus\.exe\sasktgt\s\/user\:/ nocase ascii wide
        // Description: acts as an SMB server (instead of DCOM) to relay Kerberos AP-REQ to CIFS or HTTP
        // Reference: https://github.com/decoder-it/KrbRelay-SMBServer
        $string30 = "The Relaying Kerberos Framework - SMB Server edition by @decoder_it" nocase ascii wide
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
