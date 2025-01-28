rule badrats
{
    meta:
        description = "Detection patterns for the tool 'badrats' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "badrats"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string1 = /\sbadrat\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string2 = /\sbadrat_cs\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string3 = /\sbadrat_server\.py/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string4 = /\s\-o\:badrat\.xll\s/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string5 = /\/badrat\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string6 = /\/badrat_cs\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string7 = /\/badrat_server\.py/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string8 = /\/badrats\.git/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string9 = /\/dbsclrxcvg\/b\.js/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string10 = "/rats/badrat_cs/" nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string11 = /\[\!\]\sFeature\sis\sunsupported\sfor\sPS1\srats/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string12 = /\[\!\]\sNim\sand\sC\#\sare\sthe\sonly\slanguage\scapable\sof\sexecuting\sBOFS/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string13 = /\\badrat\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string14 = /\\badrat_cs\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string15 = /\\badrat_server\.py/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string16 = /\\rats\\badrat_cs\\/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string17 = /\\rats\\js_downloader\.vba/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string18 = /\\shellcode_createproc\.xml/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string19 = /\]\sCleared\sall\srat\scommand\squeues\!/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string20 = "79520C3A-4931-46EB-92D7-334DA7FC9013" nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string21 = /badrat\.smb\.hta/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string22 = /badrat\.smb\.js/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string23 = /badrat_cs\.csproj/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string24 = /badrat_cs\.exe\s/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string25 = /badrat_cs\.exe\.config/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string26 = /badrat_server\.py\s/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string27 = /badrats\-c2\-initial\-access\-payloads\.html/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string28 = /badrats\-master\.zip/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string29 = /Invoke\-Bloodhound\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string30 = "Invoke-ReverseSocksProxy" nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string31 = /Invoke\-SocksProxy\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string32 = "KevinJClark/badrats" nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string33 = /rat\scommunications\sare\sNOT\sSECURE\.\sDo\snot\ssend\ssensitive\sinfo\sthrough\sthe\sC2\schannel\sunless\susing\sSSL/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string34 = /send_invoke_shellcode\(.{0,100}ratID/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string35 = /send_ratcode\(ratID\=/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string36 = /send_shellcode_msbuild_xml\(.{0,100}ratID/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string37 = /sends\sthe\sjscript\sfile\sto\sthe\srat\s\(JS\sand\sHTA\sonly\)\sto\sbe\sevaulated\sin\sline\.\sUseful\sfor\sGadget2JS\spayloads/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string38 = "set-shellcode-process default" nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string39 = /SharpDump\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string40 = /shellcode_injectproc\.xml/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string41 = "unlink -- tells the current rat to disconnect from a child rat given a local file or UNC path" nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string42 = /xor_crypt_and_encode\(/ nocase ascii wide
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
