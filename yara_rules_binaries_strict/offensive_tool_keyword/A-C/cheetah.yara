rule cheetah
{
    meta:
        description = "Detection patterns for the tool 'cheetah' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cheetah"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string1 = /\s\-p\spwd1\.list\spwd2\.list\s/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string2 = /\/big_shell_pwd\.7z/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string3 = /\/cheetah\.git/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string4 = /\/cheetah\.py/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string5 = /\\big_shell_pwd\.7z/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string6 = /\\cheetah\.py/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string7 = /\\cheetah\-master\.zip/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string8 = "5a1f9b0e-9f7c-4673-bf16-4740707f41b7" nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string9 = /a\svery\sfast\sbrute\sforce\swebshell\spassword\stool\./ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string10 = /cheetah\.py\s\-/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string11 = /git\sclone\s.{0,100}\s\/tmp\/cheetah/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string12 = /http\:\/\/localhost\/shell\.jsp\?pwd\=System\.out\.println\(/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string13 = "run --rm -it xshuden/cheetah" nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string14 = "shmilylty/cheetah" nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string15 = /sunnyelf\/cheetah\/archive\/master\.zip/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string16 = /sunnyelf\[\@hackfun\.org\]/ nocase ascii wide
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
