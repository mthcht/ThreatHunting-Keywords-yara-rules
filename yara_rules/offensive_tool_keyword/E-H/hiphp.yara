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
        $string1 = /.{0,1000}\shiphp\-cli\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string2 = /.{0,1000}\shiphp\-desktop\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string3 = /.{0,1000}\s\-i\s\-t\shiphp:latest.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string4 = /.{0,1000}\/hiphp\.git.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string5 = /.{0,1000}\/hiphp\-cli\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string6 = /.{0,1000}\/hiphp\-desktop\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string7 = /.{0,1000}\/hiphp\-main.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string8 = /.{0,1000}\\hiphp\-cli\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string9 = /.{0,1000}\\hiphp\-desktop\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string10 = /.{0,1000}docker\sbuild\s\-t\shiphp:latest.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string11 = /.{0,1000}docker.{0,1000}\/hiphp:latest.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string12 = /.{0,1000}e7370f93d1d0cde622a1f8e1c04877d8463912d04d973331ad4851f04de6915a.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string13 = /.{0,1000}from\shiphp\simport\s.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string14 = /.{0,1000}hiphp\s.{0,1000}\-\-url.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string15 = /.{0,1000}hiphp\.hiphplinkextractor.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string16 = /.{0,1000}hiphp\.hiphpversion.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string17 = /.{0,1000}hiphp\-0\.3\.4\.deb.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string18 = /.{0,1000}hiphp\-0\.3\.5\.deb.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string19 = /.{0,1000}hiphp\-0\.3\.6\.deb.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string20 = /.{0,1000}hiphp\-1\..{0,1000}\..{0,1000}\.deb.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string21 = /.{0,1000}hiphp\-cli\.bat.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string22 = /.{0,1000}hiphp\-desktop\.bat.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string23 = /.{0,1000}hiphp\-termux\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string24 = /.{0,1000}hiphp\-tk\.bat.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string25 = /.{0,1000}Killing\sngrok\stunnel.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string26 = /.{0,1000}pip\sinstall\shiphp.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string27 = /.{0,1000}python\smain\.py\s\-\-KEY\=.{0,1000}\s\-\-URL\=.{0,1000}127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string28 = /.{0,1000}run\-hiphp\-tk\.sh.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string29 = /.{0,1000}share\/hiphp\.py.{0,1000}/ nocase ascii wide
        // Description: The BackDoor of HIPHP gives you the power to control websites based on PHP using HTTP/HTTPS protocol. By sending files - tokens and commands through port 80s POST/GET method - users can access a range of activities such as downloading and editing files. It also allows for connecting to Tor networks with password protection for extra security.
        // Reference: https://github.com/yasserbdj96/hiphp
        $string30 = /.{0,1000}yasserbdj96\/hiphp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
