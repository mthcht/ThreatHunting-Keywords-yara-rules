rule MirrorDump
{
    meta:
        description = "Detection patterns for the tool 'MirrorDump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MirrorDump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string1 = /\sMirrorDump\.exe/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string2 = /\/lsass\.rar/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string3 = /\/lsass\.zip/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string4 = /\/MirrorDump\.exe/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string5 = /\/MirrorDump\.git/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string6 = /\[\!\]\sFailed\sto\sfake\sNtOpenProcess\son\sLSASS\sPID/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string7 = /\[\!\]\sFailed\sto\sget\sLSASS\shandle\,\sbailing\!/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string8 = /\[\+\]\sMinidump\ssuccessfully\ssaved\sto\smemory/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string9 = /\[\=\]\sDumping\sLSASS\smemory/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string10 = /\\lsass\.rar/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string11 = /\\lsass\.zip/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string12 = /\\MiniDumpToMem\.cs/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string13 = /\\MirrorDump\.csproj/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string14 = /\\MirrorDump\.exe/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string15 = /\\MirrorDump\.sln/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string16 = /\\MirrorDump\\MinHook/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string17 = /\\MirrorDump\\MiniDump\\/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string18 = /\\MirrorDump\-master/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string19 = /58338E42\-6010\-493C\-B8C8\-2FD2CFC30FFB/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string20 = /CCob\/MirrorDump/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string21 = /minidumptomemsharp\.lsa\.lsaproviderduper\.boo/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string22 = /NotLSASS\.zip/ nocase ascii wide
        // Description: LSASS dumping tool that uses a dynamically compiled LSA plugin to grab an lsass handle and API hooking for capturing the dump in memory
        // Reference: https://github.com/CCob/MirrorDump
        $string23 = /NotLSASS1\.zip/ nocase ascii wide
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
