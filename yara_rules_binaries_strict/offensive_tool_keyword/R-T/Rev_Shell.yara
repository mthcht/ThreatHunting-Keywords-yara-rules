rule Rev_Shell
{
    meta:
        description = "Detection patterns for the tool 'Rev-Shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rev-Shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string1 = /\srevshell\.py/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string2 = /\\"Generate\sreverse\sshell\spayloads\.\\"/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string3 = /\/Rev\-Shell\.git/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string4 = /\/revshell\.py/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string5 = /\\nGenerated\spayload\:/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string6 = /\\revshell\.py/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string7 = /\|\/bin\/sh\s\-i\s2\>\&1\|nc\s.{0,100}\s\>\/tmp\/f/
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string8 = "a280f960cb4fc01ec2dbb4fe56f17122523878a9ece3713868244fbd95e7d7e6" nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string9 = /bash\s\-i\s\&\>\/dev\/tcp\/.{0,100}\s\<\&1/
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string10 = /generate_payload\(language\,\sip\,\sport\)/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string11 = /nc\s\-e\s\/bin\/sh\s.{0,100}\s/
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string12 = /powershell\s\-c\s.{0,100}New\-Object\sSystem\.Net\.Sockets\.TCPClient\(\\".{0,100}\$sendback\s\=\s\(iex\s.{0,100}\$data.{0,100}\s2\>\&1\s\|\sOut\-String/ nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string13 = /s\=socket\.socket\(socket\.AF_INET\,socket\.SOCK_STREAM\)\;s\.connect\(.{0,100}os\.dup2\(s\.fileno.{0,100}pty\.spawn\(\\"\/bin\/bash/
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string14 = /TF\=.{0,100}mkfifo\s.{0,100}\s\&\&\stelnet\s.{0,100}\s0\<.{0,100}\|\s\/bin\/sh\s1\>/
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string15 = "washingtonP1974/Rev-Shell" nocase ascii wide
        // Description: Basic script to generate reverse shell payloads
        // Reference: https://github.com/washingtonP1974/Rev-Shell
        $string16 = /www\.revshells\.com/ nocase ascii wide
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
