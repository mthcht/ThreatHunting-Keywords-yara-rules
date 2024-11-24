rule hookchain
{
    meta:
        description = "Detection patterns for the tool 'hookchain' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hookchain"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string1 = /\/hookchain_finder64\.exe/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string2 = /\/HookChain_msg\.exe/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string3 = /\[\+\]\sCreating\sHookChain\simplants/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string4 = /\[\+\]\sCreating\sHookChain\simplants/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string5 = /\[\+\]\sHookChain\simplanted\!\s\\\\o\// nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string6 = /\[\+\]\sHookChain\simplanted\!/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string7 = /\[\+\]\sListing\sntdll\sNt\/Zw\sfunctions/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string8 = /\\HookChain\.vcxproj/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string9 = /\\hookchain_finder64\.c/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string10 = /\\hookchain_finder64\.exe/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string11 = /\\HookChain_msg\.exe/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string12 = /\\HookChain_msg\.sln/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string13 = /\]\sInjecting\sremote\sshellcode/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string14 = "461df8ad66af0d6635bc8e389f307569c01f1b589319b8a887578b221c943b03" nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string15 = /72e0ca8ac2312f9bda3badfc199df5bd0a224dcbdfa681a6fda0e3f5a774f7b6\s\?\s\?/ nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string16 = "a43682fd04ffe7d7a41a4b9a1afeddda45f2a74cca6632bbf4d7d6c110e2ff80" nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string17 = "B0C08C11-23C4-495F-B40B-14066F12FAAB" nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string18 = "helviojunior/hookchain" nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string19 = "HookChainFinder M4v3r1ck by Sec4US Team" nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string20 = "Message Box created from HookChain" nocase ascii wide
        // Description: Bypassing EDR Solutions
        // Reference: https://github.com/helviojunior/hookchain
        $string21 = "Process injected MessageBox" nocase ascii wide
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
