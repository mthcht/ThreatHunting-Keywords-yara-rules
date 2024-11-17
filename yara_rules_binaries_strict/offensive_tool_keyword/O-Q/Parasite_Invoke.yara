rule Parasite_Invoke
{
    meta:
        description = "Detection patterns for the tool 'Parasite-Invoke' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Parasite-Invoke"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string1 = /\sParasite\sInvoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string2 = /\.\sNice\sassembly\s\:D\s\./ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string3 = /\.exe\s\-\-path\sC\:\\\s\-r\s\-\-method\sVirtualAlloc/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string4 = /\/Parasite\sInvoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string5 = /\/Parasite\%20Invoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string6 = /\/Parasite\-Invoke\.git/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string7 = /\\Parasite\sInvoke\.csproj/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string8 = /\\Parasite\sInvoke\.exe/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string9 = /\\Parasite\sInvoke\.pdb/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string10 = /\\Parasite\sInvoke\.sln/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string11 = /\\Parasite\sInvoke\\/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string12 = /\\Parasite\-Invoke\-main/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string13 = /\=\=\=PARASITE\sINVOKE/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string14 = /7CEC7793\-3E22\-455B\-9E88\-94B8D1A8F78D/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string15 = /https\:\/\/pastebin\.com\/9JyjcMAH/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string16 = /https\:\/\/pastebin\.com\/iBeTbXCw/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string17 = /Michael\sZhmaylo\s\(github\.com\// nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string18 = /MzHmO\/Parasite\-Invoke/ nocase ascii wide
        // Description: Hide your P/Invoke signatures through other people's signed assemblies
        // Reference: https://github.com/MzHmO/Parasite-Invoke
        $string19 = /Parasite\sInvoke_\.\-\'/ nocase ascii wide
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
