rule Gecko
{
    meta:
        description = "Detection patterns for the tool 'Gecko' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gecko"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string1 = /\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,100}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}.{0,100}\$\{\\"\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53\\"\}/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string2 = /\$2y\$10\$ACTF7jbtyof6YoTCqitwLOxQ9II8xitPKC4pNi6SQjZM3HXkKiCZ/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string3 = /\/gecko\-new\.php/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string4 = /\/gecko\-old\.php/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string5 = /\\gecko\-new\.php/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string6 = /\\gecko\-old\.php/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string7 = "21c9869676708d67b55fe9f17c7c43fadaf3a9b27bf013b9bb0ba673d70da013" nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string8 = "618eea76cd6f9ea8adcaa2e96236c352db4a034e52bd3d1a1140012d5510389b" nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string9 = "9f25da71d888618eb41ff007df64538c1f9a81a717701e66481ef9b14394e09d" nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string10 = "a0bf933c2db4c92515bd4bcbfd5e7e07baca998423bdc11056f5271e3b93aef5" nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string11 = /chmod\s\+x\spwnkit/
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string12 = /https\:\/\/github\.com\/MadExploits\/Privelege\-escalation\/raw\/main\/pwnkit/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string13 = /https\:\/\/phppasswordhash\.com\// nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string14 = /import\ssocket\,subprocess\,os\;s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,100}subprocess\.call\(\[\\"\\"\/bin\/sh/
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string15 = "MadExploits/Gecko" nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string16 = /mkfifo\s\/tmp\/f\;cat\s\/tmp\/f\|\/bin\/sh\s\-i\s2\>\&1\|nc\s/
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string17 = /pwnkit\s\\"id\\"\s\>\s\.mad\-root/ nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string18 = "pwnkit \"useradd " nocase ascii wide
        // Description: Gecko Backdoor is a  web php backdoor
        // Reference: https://github.com/MadExploits/Gecko
        $string19 = /wget\shttp.{0,100}\s\-O\spwnkit/ nocase ascii wide
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
