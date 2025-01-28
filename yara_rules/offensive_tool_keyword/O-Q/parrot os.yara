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
        $string1 = " parrot main "
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string2 = /\sparrot\.run\//
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string3 = " parrot-backports "
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string4 = " parrot-security "
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string5 = /\/deb\.parrot\.sh\//
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string6 = /\/parrot\/iso\/.{0,1000}\.iso/
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string7 = "/parrot-mirror/"
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string8 = "/parrot-on-docker/"
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string9 = "/parrotsec/"
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string10 = /bunny\.deb\.parrot\.sh\//
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string11 = /edge1\.parrot\.run/
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string12 = /mirrors\.aliyun\.com\/parrot/
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string13 = /parrot.{0,1000}security\.vdi/
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string14 = /parrotsec\.org\/download\//
        // Description: Parrot OS is a Debian-based. security-oriented Linux distribution that is designed for ethical hacking. penetration testing and digital forensics.
        // Reference: https://www.parrotsec.org/download/
        $string15 = /Parrot\-security\-.{0,1000}\.iso/

    condition:
        any of them
}
