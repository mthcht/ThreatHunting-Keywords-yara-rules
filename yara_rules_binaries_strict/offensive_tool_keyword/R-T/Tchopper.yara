rule Tchopper
{
    meta:
        description = "Detection patterns for the tool 'Tchopper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tchopper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string1 = /\stmp_payload\.txt/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string2 = /\#1\s\-\sSmuggling\sbinary\svia\sService\sDisplayName/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string3 = /\#2\s\-\sSmuggling\sbinary\svia\sWMI/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string4 = /\/TChopper\.git/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string5 = /\[\+\]\stask\shas\sbeen\screated\ssuccessfully\s\s\.\.\!/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string6 = /\[\-\>\]\ssending\spayload\.\.as\schuncks/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string7 = /\\Public\\chop\.enc/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string8 = /\\TChopper\\chopper\./ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string9 = /\\Tchopper\-main\.zip/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string10 = /\\tmp_payload\.txt/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string11 = /chop\starget\susername\spassword\sdomain\sfilename\schd\swmi/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string12 = /chopper\.exe\s\-m/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string13 = /chopper\.exe\s\-s/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string14 = /chopper\.exe\s\-w/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string15 = /cmd\.exe\s\/c\spowershell\s\-command\s\\"Get\-Service\s.{0,100}chopper/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string16 = /Data\sName\=\\"ServiceName\\"\>chopper\<\/Data\>/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string17 = /Data\sName\=\\"ServiceName\\"\>final_seg\<\/Data\>/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string18 = /Data\sName\=\\"ServiceName\\"\>let\sme\sin\<\/Data\>/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string19 = /lawrenceamer\/Tchopper/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string20 = /\'svc_smuggling\'/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string21 = /Technique\s\#1\s\-\sChop\sChop\s\-\sCreate\/delete/ nocase ascii wide
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
