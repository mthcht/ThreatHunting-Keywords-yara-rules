rule wstunnel
{
    meta:
        description = "Detection patterns for the tool 'wstunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wstunnel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string1 = /\sclient\s\-\-http\-upgrade\-path\-prefix\s.{0,1000}wss/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string2 = /\sclient\s\-L\ssocks5\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string3 = /\sclient\s\-L\sstdio\:\/\/.{0,1000}\sws\:\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string4 = /\sclient\s\-L\stcp\:\/\/.{0,1000}\swss\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string5 = /\sclient\s\-L\s\'tproxy\+tcp\:\/\/.{0,1000}\s\-L\s\'tproxy\+udp\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string6 = /\sclient\s\-L\s\'udp\:\/\/.{0,1000}\swss\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string7 = /\sclient\s\-R\s\'tcp\:\/\/\[\:\:\]\:/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string8 = /\s\-\-connection\-min\-idle\s.{0,1000}\sws\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string9 = /\s\-\-local\-to\-remote\ssocks5\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string10 = /\s\-\-local\-to\-remote\sstdio\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string11 = /\s\-\-local\-to\-remote\stcp\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string12 = /\s\-\-local\-to\-remote\stproxy\+tcp\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string13 = /\s\-\-local\-to\-remote\stproxy\+udp\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string14 = /\s\-\-local\-to\-remote\sudp\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string15 = /\s\-\-remote\-to\-local\ssocks\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string16 = /\s\-\-remote\-to\-local\stcp\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string17 = /\s\-\-remote\-to\-local\sudp\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string18 = /\s\-\-restrict\-to\slocalhost\:.{0,1000}\swss\:\/\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string19 = /\sserver\s\-\-restrict\-http\-upgrade\-path\-prefix\s.{0,1000}wss/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string20 = /\sserver\swss\:\/\/\[\:\:\]\:/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string21 = /\sws\:\/\/\[\:\:\]\:/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string22 = /\swss\:\/\/0\.0\.0\.0\:/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string23 = /\swstunnel\.exe/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string24 = /\/home\/app\/wstunnel/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string25 = /\/wstunnel\swstunnel/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string26 = /\/wstunnel\.exe/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string27 = /\/wstunnel\.git/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string28 = /\/wstunnel\/certs\// nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string29 = /\/wstunnel\:latest/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string30 = /\:\/\/wstunnel\.server\.com/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string31 = /\\wstunnel\.exe/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string32 = /\\wstunnel\\certs\\/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string33 = /2ab5af4a7fa7d14b4a4facef9b4d80bd3ada7e20c36712ece61ce9c294107745/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string34 = /4e6e01948bbd969f58b1535f30efc9b75c63e0d362b9487b9ea8ebe768ce893e/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string35 = /7a51ed902fc804066c4617af21d0325cceebce588ca66709c697916ce5214e64/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string36 = /7cda14dc04bb731f09880db6310c9d9d4ee96176931627f322ec725cde6bd18b/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string37 = /9ad6daccfd1d3d349a93950f599eed59280268431d76bad7fc624d4cd4c565a5/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string38 = /Cannot\sstart\swstunnel\sserver\:/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string39 = /curl\s\-x\ssocks5h\:\/\/127\.0\.0\.1\:/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string40 = /erebe\/wstunnel/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string41 = /f7267a8880e45961219a6204a3a8ae5fff31e495f3f930e487f80cf89850f16f/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string42 = /h3GywpDrP6gJEdZ6xbJbZZVFmvFZDCa4KcRd/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string43 = /ssh\s\-o\sProxyCommand\=\"wstunnel/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string44 = /Starting\swstunnel\sserver\sv/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string45 = /target\/debug\/wstunnel/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string46 = /wstunnel\sclient\s/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string47 = /wstunnel\sserver\s/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string48 = /wstunnel.{0,1000}\s\-\-restrict\-to\s127\.0\.0\.1\:22/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string49 = /wstunnel.{0,1000}cert\.pem/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string50 = /wstunnel.{0,1000}key\.pem/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string51 = /wstunnel\.exe\s/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string52 = /wstunnel\/pkgs\/container\/wstunnel/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string53 = /wstunnel_.{0,1000}_darwin_amd64\.tar\.gz/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string54 = /wstunnel_.{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string55 = /wstunnel_.{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string56 = /wstunnel_.{0,1000}_linux_armv7\.tar\.gz/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string57 = /wstunnel_.{0,1000}_windows_386\.tar\.gz/ nocase ascii wide
        // Description: Tunnel all your traffic over websocket protocol - Bypass firewalls/DPI - Static binary available
        // Reference: https://github.com/erebe/wstunnel
        $string58 = /wstunnel_.{0,1000}_windows_amd64\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}
