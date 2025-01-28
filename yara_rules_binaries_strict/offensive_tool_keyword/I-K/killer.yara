rule killer
{
    meta:
        description = "Detection patterns for the tool 'killer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "killer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string1 = /\skiller\.cpp\s/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string2 = /\skiller\.exe/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string3 = /\sreverse\-shellcode\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string4 = /\sshellcode\-xor\.py/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string5 = /\/killer\.exe/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string6 = /\/Killer\.git/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string7 = /\/OUT\:killer\.exe/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string8 = /\/reverse\-shellcode\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string9 = /\/shellcode\-xor\.py/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string10 = /\[\+\]\sDetecting\shooks\sin\snew\sntdll\smodule/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string11 = /\\killer\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string12 = /\\killer\.exe/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string13 = /\\nReversed\sshellcode\:\\n/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string14 = /\\reverse\-shellcode\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string15 = /\\shellcode\-xor\.py/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string16 = "0xHossam/Killer" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string17 = "26695658d9cd9108527921dc351de3b717d37d849d0390ad7b9a6f0bb4d474a9" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string18 = "3d0ab78d9ceb76cae4a8a600ebfcf3e078ccc5b19038edf73fcf9653f26d7064" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string19 = "Author => Hossam Ehab / EDR/AV evasion tool" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string20 = /Author\:\sHossam\sEhab\s\-\sfacebook\.com\/0xHossam/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string21 = "b84798b914f570f9b52bf3fe754c2559795aa6c3daa4c4344f4bce69f5f759d9" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string22 = "c0e4815479886635396488093956d7926bcd803a4651c715398cf4446a05a55f" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string23 = "Hit enter to run shellcode/payload without creating a new thread" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string24 = /Hossam\sEhab\s\/\sAn\sEDR\s\(End\sPoint\sDetection\s\&\sResponse\)\sEvasion\sTool/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string25 = "Killer tool for EDR/AV Evasion --> IAT Obfuscation" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string26 = /Sandbox\sdetected\s\-\sFilename\schanged\s\:\(\s/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string27 = "Shellcode & key Decrypted after stomping" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string28 = /\'W\'\,\'i\'\,\'n\'\,\'d\'\,\'o\'\,\'w\'\,\'s\'\,\'\\\\\'\,\'S\'\,\'y\'\,\'s\'\,\'t\'\,\'e\'\,\'m\'\,\'3\'\,\'2\'\,/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string29 = "windows/x64/meterpreter/reverse_tcp" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string30 = "b84798b914f570f9b52bf3fe754c2559795aa6c3daa4c4344f4bce69f5f759d9" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string31 = "c40e57334fa15d54a9c0ebeb4345e3e2e9f26ba044b5fe923625a9f66e55c360" nocase ascii wide
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
