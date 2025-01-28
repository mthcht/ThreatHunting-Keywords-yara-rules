rule hiphp
{
    meta:
        description = "Detection patterns for the tool 'hiphp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hiphp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string1 = /\shiphp\-cli\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string2 = /\shiphp\-desktop\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string3 = " -i -t hiphp:latest" nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string4 = /\/hiphp\.git/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string5 = /\/hiphp\-cli\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string6 = /\/hiphp\-desktop\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string7 = "/hiphp-main" nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string8 = /\\hiphp\-cli\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string9 = /\\hiphp\-desktop\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string10 = "docker build -t hiphp:latest" nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string11 = /docker.{0,100}\/hiphp\:latest/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string12 = "e7370f93d1d0cde622a1f8e1c04877d8463912d04d973331ad4851f04de6915a" nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string13 = "from hiphp import " nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string14 = /hiphp\s.{0,100}\-\-url/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string15 = /hiphp\.hiphplinkextractor/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string16 = /hiphp\.hiphpversion/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string17 = /hiphp\-0\.3\.4\.deb/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string18 = /hiphp\-0\.3\.5\.deb/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string19 = /hiphp\-0\.3\.6\.deb/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string20 = /hiphp\-1\..{0,100}\..{0,100}\.deb/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string21 = /hiphp\-cli\.bat/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string22 = /hiphp\-desktop\.bat/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string23 = /hiphp\-termux\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string24 = /hiphp\-tk\.bat/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string25 = "Killing ngrok tunnel" nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string26 = "pip install hiphp" nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string27 = /python\smain\.py\s\-\-KEY\=.{0,100}\s\-\-URL\=.{0,100}127\.0\.0\.1/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string28 = /run\-hiphp\-tk\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string29 = /share\/hiphp\.py/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string30 = "yasserbdj96/hiphp" nocase ascii wide
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
