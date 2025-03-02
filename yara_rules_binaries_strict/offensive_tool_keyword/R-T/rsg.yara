rule rsg
{
    meta:
        description = "Detection patterns for the tool 'rsg' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsg"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string1 = " nc -n -v -l -s "
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string2 = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\./ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string3 = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string4 = "/bin/sh -i <&3 >&3 2>&3"
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string5 = "/usr/local/bin/rsg"
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string6 = "64cd8640e2b53358f8fbafbcbded6db53e1acd49fe4ccc8196c8ed17c551bc70" nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string7 = "b3804cac36175125199ddd8f6840749ead5c723d9641670d244d0a487fcf555c" nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string8 = "ebdac49d15f37cc60cb5e755b10743512ececf134126e0ac4a024cb1149ae76f" nocase ascii wide
        // Description: A tool to generate various ways to do a reverse shell
        // Reference: https://github.com/mthbernardes/rsg
        $string9 = /mthbernardes.{0,100}rsg/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string10 = "mthbernardes/rsg" nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string11 = "nc -c /bin/sh "
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string12 = /php\s\-r\s.{0,100}fsockopen.{0,100}exec\(.{0,100}\/bin\/sh/
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string13 = /powershell\s\-nop\s\-c\s\\"\\"\$client\s\=\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string14 = /ruby\s\-rsocket\s\-e\s\'.{0,100}\=TCPSocket\.new\(/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string15 = /socat\.exe\s\-d\s\-d\sTCP4\:/ nocase ascii wide
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
