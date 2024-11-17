rule donpapi
{
    meta:
        description = "Detection patterns for the tool 'donpapi' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "donpapi"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string1 = /\srun\sdonpapi/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string2 = /\.py\s\s\-credz\s.{0,100}\.txt\s.{0,100}\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string3 = /\/chrome_decrypt\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string4 = /\/creddump7\// nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string5 = /\/DonPAPI\.git/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string6 = /\/DonPAPI\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string7 = /\/firefox_decrypt\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string8 = /\/lastpass\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string9 = /\/login\-securite\/DonPAPI/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string10 = /28a2e9e1ab772d0017aa994feae882eeea526fcbcb2f929ec410eabcf2912c14/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string11 = /4860280fe3039b1f65dad29dbcbb674c6f41004c34e99d382b824b4004aacdd0/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string12 = /9bfad1d826217983cbf0bb46c9578f592002d7893e0e359ef30f888c3693ad3c/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string13 = /a2b0e31afa53dfc587fa9e80abddbb6bb01d1050d5e68359f6f298a84fa6625e/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string14 = /c1f971aa959ea7722c8bc41a6677ad83230e129d69424c16835c3d000756582e/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string15 = /c35aa22a683405cb282d97f125cb785cd7767591c96f4d00a27e5ac92b494f6c/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string16 = /Decrypting\sDPAPI\sdata\swith\smasterkey\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string17 = /domcachedump\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string18 = /donapapi\s\-pvk\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string19 = /donpapi\s\-credz\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string20 = /donpapi\.lazagne\.softwares/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string21 = /donpapi\.myseatbelt\'/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string22 = /DonPAPI\.py\s/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string23 = /donpapi\-master\.zip/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string24 = /dpapi_pick\/credhist\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string25 = /dump_CREDENTIAL_MSOFFICE/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string26 = /dump_CREDENTIAL_TASKSCHEDULER\(/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string27 = /dump_CREDENTIAL_TASKSCHEDULER/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string28 = /dump_CREDENTIAL_TSE/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string29 = /dump_VAULT_INTERNET_EXPLORER/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string30 = /dump_VAULT_NGC_LOCAL_ACCOOUNT/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string31 = /dump_VAULT_WIN_BIO_KEY/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string32 = /e292dfd2c82421324fdc94d544472f78528bdd862148509cab29ecdcbf9d8c4c/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string33 = /f93277bd46aec52cc14875cb9439a8ab5f226cf4f857196e2b423391dd67ec93/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string34 = /Get_DPAPI_Protected_Files/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string35 = /GetChromeSecrets/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string36 = /hashdump\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string37 = /lsasecrets\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string38 = /manager\/keepass\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string39 = /manager\/mRemoteNG\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string40 = /memorydump\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string41 = /mRemoteNG\-local\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string42 = /myseatbelt\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string43 = /ppypykatz\.py/ nocase ascii wide
        // Description: Dumping DPAPI credentials remotely
        // Reference: https://github.com/login-securite/DonPAPI
        $string44 = /SAM\shashes\sextraction\sfor\suser\s.{0,100}\sfailed/ nocase ascii wide
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
