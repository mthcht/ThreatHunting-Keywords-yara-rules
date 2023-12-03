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
        $string1 = /.{0,1000}\sparrot\smain\s.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string2 = /.{0,1000}\sparrot\.run\/.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string3 = /.{0,1000}\sparrot\-backports\s.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string4 = /.{0,1000}\sparrot\-security\s.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string5 = /.{0,1000}\/deb\.parrot\.sh\/.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string6 = /.{0,1000}\/parrot\/iso\/.{0,1000}\.iso.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string7 = /.{0,1000}\/parrot\-mirror\/.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string8 = /.{0,1000}\/parrot\-on\-docker\/.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string9 = /.{0,1000}\/parrotsec\/.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string10 = /.{0,1000}bunny\.deb\.parrot\.sh\/.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string11 = /.{0,1000}edge1\.parrot\.run.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string12 = /.{0,1000}mirrors\.aliyun\.com\/parrot.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string13 = /.{0,1000}parrot.{0,1000}security\.vdi.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string14 = /.{0,1000}parrotsec\.org\/download\/.{0,1000}/ nocase ascii wide
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string15 = /.{0,1000}Parrot\-security\-.{0,1000}\.iso.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
