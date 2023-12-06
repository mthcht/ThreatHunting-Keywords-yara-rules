rule parrot_os
{
    meta:
        description = "Detection patterns for the tool 'parrot os' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "parrot os"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string1 = /\sparrot\smain\s/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string2 = /\sparrot\.run\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string3 = /\sparrot\-backports\s/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string4 = /\sparrot\-security\s/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string5 = /\/deb\.parrot\.sh\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string6 = /\/parrot\/iso\/.{0,1000}\.iso/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string7 = /\/parrot\-mirror\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string8 = /\/parrot\-on\-docker\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string9 = /\/parrotsec\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string10 = /bunny\.deb\.parrot\.sh\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string11 = /edge1\.parrot\.run/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string12 = /mirrors\.aliyun\.com\/parrot/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string13 = /parrot.{0,1000}security\.vdi/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string14 = /parrotsec\.org\/download\// nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string15 = /Parrot\-security\-.{0,1000}\.iso/ nocase ascii wide

    condition:
        any of them
}
