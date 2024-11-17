rule NamedPipeMaster
{
    meta:
        description = "Detection patterns for the tool 'NamedPipeMaster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NamedPipeMaster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string1 = /\/NamedPipeMaster\.git/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string2 = /\/NamedPipeMaster\/tarball\// nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string3 = /\/NamedPipeMaster\/zipball\// nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string4 = /\/NamedPipeMasterBase\// nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string5 = /\\\\Device\\\\NamedPipe\\\\NamedPipeMaster/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string6 = /\\Device\\NamedPipe\\NamedPipeMaster/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string7 = /\\NamedPipeEventDatabase\.cpp/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string8 = /\\NamedPipeMaster\.sln/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string9 = /\\NamedPipeMasterBase\\/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string10 = /\\NamedPipeMaster\-main/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string11 = /089e1f51fe8751dfbbc11c8ffd8d7b6121ac025d8e0c0c2f082e3d976d6af948/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string12 = /195cbf85cbf9fc7dcd011b2658819cf3350195f61021cb7c5a6f6e32cba15f03/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string13 = /2787cc9e36cc2aebada79515e19ca4daf36887a091ec8f41af187c96df4147af/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string14 = /40ab3cf285a8ee70b183bd6f12c2b2fa0890df82ed38ce7833263781cbf37a19/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string15 = /585e550d0435ab335e6c7fdfb7a609b7b8ead766fc3ee7ef1f93113b1d51e5d3/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string16 = /5C87B2E6\-8D24\-4F1D\-AB85\-FC659F452AD0/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string17 = /733a16c2eb4095398eab1a92ca5cea56a935f3df05a100fec3a1decda26d1e3f/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string18 = /80bba5f788f3f4a7fa0e3a516fdd0dcd7eb1553065ee224090f18dec032a04cd/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string19 = /8a15e1d1589aeac183ce00830f32e9399f88f1db811f00e537a5fac1ac8002a0/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string20 = /95dcf74d21d688a7f2b887af56aeeae19c0d788ed863746f1edf19539a67ad37/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string21 = /a0b87b7223b946059d61f7c955981ad9715a243f4b4116dd2dcb4352f9a02460/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string22 = /act\sas\sa\snamed\spipe\sserver\sto\sbe\sconnected\sby\sother\sclients/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string23 = /C2F24BBD\-4807\-49F5\-B5E2\-77FF0E8B756B/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string24 = /caa3f53715c68033d72a623dfcc2412cc86bce077d6081685ead3b1498e8b804/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string25 = /d6edddd2dcac14dfe70c6b396236d6d3a95b0c1f6fe8fec38381049f3823bdb6/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string26 = /E7BFFEE1\-07C1\-452C\-8AF8\-6AD30B1844FF/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string27 = /e95eb9af49be9d5c4c95a832bd36c192a570f0dd649cfd24b81de5e3e6262236/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string28 = /ea552615337ba9becf9c1341f4ad2556b204dca25982c123b2cfd6e218192b49/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string29 = /f9e0d5910c1883ad6c902d895ebd813018ad7e5a0b4f5988d0c2ed861e9e08de/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string30 = /Information\sCollection\svia\sDLL\sInjection\s\(Ring3\sHook\)/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string31 = /inject\s.{0,100}\.dll\sinto\sa\sprocess\sas\sa\sproxy\sto\sinteract\swith\sthe\starget\snamed\spipe\sserver/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string32 = /Inject\sinto\sthe\sproxy\sprocess\sand\slet\sit\sopen\sa\snamed\spipe\sserver\./ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string33 = /keep\smonitoring\snamed\spipe\sactivities\suntil\senter\sis\spressed/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string34 = /NamedPipeMaster\/releases\/download\// nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string35 = /NamedPipeMaster\-32bit\.zip/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string36 = /NamedPipeMaster\-32bit\\/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string37 = /NamedPipeMaster\-64bit\.zip/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string38 = /NamedPipeMaster\-64bit\\/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string39 = /NamedPipeMasterLogger/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string40 = /NamedPipeMaster\-main\.zip/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string41 = /NamedPipePoker\.cpp/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string42 = /NamedPipePoker\.h/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string43 = /NamedPipeProxyPoker/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string44 = /Offensive\-Windows\-IPC\-1\-NamedPipes\./ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string45 = /PeekNamedPipe\(fromPipe/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string46 = /\'PipeName\'\>\\NamedPipeMaster/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string47 = /RING0_ANONYMOUS_PIPE/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string48 = /Ring0NamedPipeFilter\s/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string49 = /Ring0NamedPipeFilter\.h/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string50 = /Ring3NamedPipeConsumer\.exe/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string51 = /Ring3NamedPipeMonitor/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string52 = /Ring3NamedPipeMonitor\.dll/ nocase ascii wide
        // Description: a tool used to analyze  monitor and interact with named pipes - allows dll injection and impersonation
        // Reference: https://github.com/zeze-zeze/NamedPipeMaster
        $string53 = /zeze\-zeze\/NamedPipeMaster/ nocase ascii wide
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
