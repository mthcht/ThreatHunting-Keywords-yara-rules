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
        $string1 = /KevinJClark\/badrats/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string2 = /\/badrats\.git/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string3 = /badrats\-master\.zip/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string4 = /\/badrat_server\.py/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string5 = /\\badrat_server\.py/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string6 = /\sbadrat_server\.py/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string7 = /badrat_server\.py\s/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string8 = /\\badrat\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string9 = /\/badrat\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string10 = /\sbadrat\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string11 = /badrat\.smb\.hta/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string12 = /badrat\.smb\.js/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string13 = /\\rats\\js_downloader\.vba/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string14 = /\\rats\\badrat_cs\\/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string15 = /\/rats\/badrat_cs\// nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string16 = /\/badrat_cs\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string17 = /\\badrat_cs\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string18 = /\sbadrat_cs\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string19 = /badrat_cs\.exe\s/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string20 = /badrat_cs\.exe\.config/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string21 = /Invoke\-SocksProxy\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string22 = /Invoke\-ReverseSocksProxy/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string23 = /\[\!\]\sFeature\sis\sunsupported\sfor\sPS1\srats/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string24 = /\[\!\]\sNim\sand\sC\#\sare\sthe\sonly\slanguage\scapable\sof\sexecuting\sBOFS/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string25 = /Invoke\-Bloodhound\.ps1/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string26 = /set\-shellcode\-process\sdefault/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string27 = /sends\sthe\sjscript\sfile\sto\sthe\srat\s\(JS\sand\sHTA\sonly\)\sto\sbe\sevaulated\sin\sline\.\sUseful\sfor\sGadget2JS\spayloads/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string28 = /\]\sCleared\sall\srat\scommand\squeues\!/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string29 = /rat\scommunications\sare\sNOT\sSECURE\.\sDo\snot\ssend\ssensitive\sinfo\sthrough\sthe\sC2\schannel\sunless\susing\sSSL/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string30 = /unlink\s\-\-\stells\sthe\scurrent\srat\sto\sdisconnect\sfrom\sa\schild\srat\sgiven\sa\slocal\sfile\sor\sUNC\spath/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string31 = /\\shellcode_createproc\.xml/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string32 = /shellcode_injectproc\.xml/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string33 = /SharpDump\.exe/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string34 = /badrats\-c2\-initial\-access\-payloads\.html/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string35 = /badrat_cs\.csproj/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string36 = /send_invoke_shellcode\(.{0,1000}ratID/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string37 = /send_ratcode\(ratID\=/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string38 = /xor_crypt_and_encode\(/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string39 = /send_shellcode_msbuild_xml\(.{0,1000}ratID/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string40 = /79520C3A\-4931\-46EB\-92D7\-334DA7FC9013/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string41 = /\/dbsclrxcvg\/b\.js/ nocase ascii wide
        // Description: control tool (C2) using Python server - Jscript - Powershell and C# implants and communicates via HTTP(S) and SMB
        // Reference: https://gitlab.com/KevinJClark/badrats
        $string42 = /\s\-o:badrat\.xll\s/ nocase ascii wide

    condition:
        any of them
}
