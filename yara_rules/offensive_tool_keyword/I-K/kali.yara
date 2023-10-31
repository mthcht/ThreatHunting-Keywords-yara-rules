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
        $string1 = /\/\#kali\-installer\-images/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string2 = /\/detail\/kali\-linux\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string3 = /\/kali\/pool\/main\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string4 = /\/kali\-linux\-2023/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string5 = /\/kali\-tools\-/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string6 = /\/nethunter\-images\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string7 = /\/raw\/kali\/main\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string8 = /\/raw\/kali\/master\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string9 = /\\kali\-linux\-2023/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string10 = /archive\-.*\.kali\.org\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string11 = /cdimage\.kali\.org\// nocase ascii wide
        // Description: Kali Linux usage with wsl - example: \system32\wsl.exe -d kali-linux /usr/sbin/adduser???
        // Reference: https://www.kali.org/
        $string12 = /\-d\skali\-linux\s/ nocase ascii wide
        // Description: Kali Linux usage with wsl - example: \system32\wsl.exe -d kali-linux /usr/sbin/adduser???
        // Reference: https://www.kali.org/
        $string13 = /home\/kali\/Downloads/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string14 = /https:\/\/gitlab\.com\/kalilinux\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string15 = /https:\/\/kali\.download\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string16 = /hub\.docker\.com\/u\/kalilinux\// nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string17 = /\-\-install\s\-d\skali\-linux/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string18 = /kali\-.*\.deb/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string19 = /kali\-linux.*\.7z/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string20 = /kali\-linux.*\.img/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string21 = /kali\-linux.*\.iso/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string22 = /kali\-linux\-.*\.torrent/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string23 = /kali\-linux\-.*\.vmdk/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string24 = /kali\-linux\-.*\.vmwarevm/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string25 = /kali\-linux\-.*\.vmx/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string26 = /kali\-linux\-.*\-installer\-amd64\.iso/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string27 = /kali\-linux\-.*\-installer\-everything\-amd64\.iso\.torrent/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string28 = /kali\-linux\-.*\-live\-everything\-amd64\.iso\.torrent/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string29 = /kali\-linux\-.*\-raspberry\-pi\-armhf\.img\.xz/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string30 = /kali\-linux\-.*\-virtualbox\-amd64\.ova/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string31 = /kali\-linux\-.*\-vmware\-amd64\.7z/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string32 = /nethunter\-.*\.torrent/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string33 = /nethunter\-.*\.zip/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string34 = /nethunter\-.*\-oos\-ten\-kalifs\-full\.zip/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string35 = /wsl\skali\-linux/ nocase ascii wide
        // Description: Kali Linux is an open-source. Debian-based Linux distribution geared towards various information security tasks. such as Penetration Testing. Security Research. Computer Forensics and Reverse Engineering
        // Reference: https://www.kali.org/
        $string36 = /www\.kali\.org\/get\-kali\// nocase ascii wide

    condition:
        any of them
}