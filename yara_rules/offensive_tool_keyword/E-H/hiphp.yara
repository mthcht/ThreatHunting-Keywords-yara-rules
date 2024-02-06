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
        $string3 = /\s\-i\s\-t\shiphp\:latest/ nocase ascii wide
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
        $string7 = /\/hiphp\-main/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string8 = /\\hiphp\-cli\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string9 = /\\hiphp\-desktop\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string10 = /docker\sbuild\s\-t\shiphp\:latest/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string11 = /docker.{0,1000}\/hiphp\:latest/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string12 = /e7370f93d1d0cde622a1f8e1c04877d8463912d04d973331ad4851f04de6915a/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string13 = /from\shiphp\simport\s/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string14 = /hiphp\s.{0,1000}\-\-url/ nocase ascii wide
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
        $string20 = /hiphp\-1\..{0,1000}\..{0,1000}\.deb/ nocase ascii wide
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
        $string25 = /Killing\sngrok\stunnel/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string26 = /pip\sinstall\shiphp/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string27 = /python\smain\.py\s\-\-KEY\=.{0,1000}\s\-\-URL\=.{0,1000}127\.0\.0\.1/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string28 = /run\-hiphp\-tk\.sh/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string29 = /share\/hiphp\.py/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string30 = /yasserbdj96\/hiphp/ nocase ascii wide

    condition:
        any of them
}
