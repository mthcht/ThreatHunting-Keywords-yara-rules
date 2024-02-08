rule gsocket
{
    meta:
        description = "Detection patterns for the tool 'gsocket' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsocket"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string1 = /\sgs\-netcat\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string2 = /\sgsocket\.io\/x/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string3 = /\sGSOCKET_SOCKS_IP/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string4 = /\sinstall\sgsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string5 = /\/bin\/gs\-netcat/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string6 = /\/etc\/systemd\/gsc/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string7 = /\/gs\-netcat\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string8 = /\/gsocket\.1/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string9 = /\/gsocket\.git/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string10 = /\/gsocket\-ssl\.h/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string11 = /\/gsocket\-tor/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string12 = /\/gsocket\-util\.c/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string13 = /\/gs\-sftp/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string14 = /\\gs\-netcat\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string15 = /\\gs\-sftp/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string16 = /blitz\s\/.{0,1000}\s.{0,1000}\/etc\// nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string17 = /blitz\s\-l/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string18 = /blitz\s\-s\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string19 = /dc3c1af9\-ea3d\-4401\-9158\-eb6dda735276/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string20 = /docker\/gsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string21 = /GS_NETCAT_BIN/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string22 = /gs\-helloworld\sgs\-pipe\sgs\-full\-pipe/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string23 = /gs\-mount\s\~\// nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string24 = /gs\-mount\s\-s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string25 = /gs\-netcat\s\&/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string26 = /gs\-netcat\s\-/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string27 = /gs\-netcat\.1/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string28 = /gsocket\s\/usr\/sbin\/sshd/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string29 = /gsocket\sopenvpn\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string30 = /gsocket\sssh\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string31 = /gsocket.{0,1000}\/gsocket\.h/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string32 = /GSOCKET.{0,1000}Lclient_gs\.log/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string33 = /gsocket\.1\.html/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string34 = /gsocket\.io\/deploy/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string35 = /gsocket\.io\/install\.sh/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string36 = /gsocket_1\..{0,1000}\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string37 = /GSOCKET_ARGS\=/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string38 = /gsocket_linux\-aarch64\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string39 = /gsocket_linux\-arm\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string40 = /gsocket_linux\-armv6\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string41 = /gsocket_linux\-armv7l\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string42 = /gsocket_linux\-i686\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string43 = /gsocket_linux\-mips32\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string44 = /gsocket_linux\-mips64\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string45 = /gsocket_linux\-mipsel\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string46 = /gsocket_linux\-x86_64\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string47 = /gsocket_macOS\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string48 = /gsocket_openbsd\-x86_x64\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string49 = /GSOCKET_SOCKS_IP\=/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string50 = /GSOCKET_SOCKS_PORT\=/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string51 = /gsocket\-1\..{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string52 = /gsocket\-tor\// nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string53 = /gsocket\-tor\\/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string54 = /gs\-root\-shell\-key\.txt/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string55 = /gs\-sftp\s\-/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string56 = /hackerschoice\/gsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string57 = /hackerschoice\/gsocket\-relay/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Mostly abused by attackers 
        // Reference: https://github.com/hackerschoice/gsocket
        $string58 = /kalilinux\/kali\-rolling/ nocase ascii wide

    condition:
        any of them
}
