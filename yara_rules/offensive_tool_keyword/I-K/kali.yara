rule kali
{
    meta:
        description = "Detection patterns for the tool 'kali' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kali"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string1 = /.{0,1000}\/\#kali\-installer\-images.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string2 = /.{0,1000}\/detail\/kali\-linux\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string3 = /.{0,1000}\/kali\/pool\/main\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string4 = /.{0,1000}\/kali\-linux\-2023.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string5 = /.{0,1000}\/kali\-tools\-.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string6 = /.{0,1000}\/nethunter\-images\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string7 = /.{0,1000}\/raw\/kali\/main\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string8 = /.{0,1000}\/raw\/kali\/master\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string9 = /.{0,1000}\\kali\-linux\-2023.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string10 = /.{0,1000}archive\-.{0,1000}\.kali\.org\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string11 = /.{0,1000}cdimage\.kali\.org\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux usage with wsl - example: \system32\wsl.exe -d kali-linux /usr/sbin/adduser???
        // Reference: https://www.kali.org/
        $string12 = /.{0,1000}\-d\skali\-linux\s.{0,1000}/ nocase ascii wide
        // Description: Kali Linux usage with wsl - example: \system32\wsl.exe -d kali-linux /usr/sbin/adduser???
        // Reference: https://www.kali.org/
        $string13 = /.{0,1000}home\/kali\/Downloads.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string14 = /.{0,1000}https:\/\/gitlab\.com\/kalilinux\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string15 = /.{0,1000}https:\/\/kali\.download\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string16 = /.{0,1000}hub\.docker\.com\/u\/kalilinux\/.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string17 = /.{0,1000}\-\-install\s\-d\skali\-linux.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string18 = /.{0,1000}kali\-.{0,1000}\.deb.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string19 = /.{0,1000}kali\-linux.{0,1000}\.7z.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string20 = /.{0,1000}kali\-linux.{0,1000}\.img.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string21 = /.{0,1000}kali\-linux.{0,1000}\.iso.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string22 = /.{0,1000}kali\-linux\-.{0,1000}\.torrent.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string23 = /.{0,1000}kali\-linux\-.{0,1000}\.vmdk.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string24 = /.{0,1000}kali\-linux\-.{0,1000}\.vmwarevm.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string25 = /.{0,1000}kali\-linux\-.{0,1000}\.vmx.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string26 = /.{0,1000}kali\-linux\-.{0,1000}\-installer\-amd64\.iso.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string27 = /.{0,1000}kali\-linux\-.{0,1000}\-installer\-everything\-amd64\.iso\.torrent.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string28 = /.{0,1000}kali\-linux\-.{0,1000}\-live\-everything\-amd64\.iso\.torrent.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string29 = /.{0,1000}kali\-linux\-.{0,1000}\-raspberry\-pi\-armhf\.img\.xz.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string30 = /.{0,1000}kali\-linux\-.{0,1000}\-virtualbox\-amd64\.ova.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string31 = /.{0,1000}kali\-linux\-.{0,1000}\-vmware\-amd64\.7z.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string32 = /.{0,1000}nethunter\-.{0,1000}\.torrent.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string33 = /.{0,1000}nethunter\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string34 = /.{0,1000}nethunter\-.{0,1000}\-oos\-ten\-kalifs\-full\.zip.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string35 = /.{0,1000}wsl\skali\-linux.{0,1000}/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string36 = /.{0,1000}www\.kali\.org\/get\-kali\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
