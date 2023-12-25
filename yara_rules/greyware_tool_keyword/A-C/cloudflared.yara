rule cloudflared
{
    meta:
        description = "Detection patterns for the tool 'cloudflared' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloudflared"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string1 = /\._tcp\.argotunnel\.com/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string2 = /\.v2\.argotunnel\.com/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string3 = /\/cloudflared\.git/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string4 = /\/cloudflared\/tunnel\// nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string5 = /\/cloudflared\-linux\-.{0,1000}\.deb/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string6 = /\/cloudflared\-linux\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string7 = /\/usr\/local\/bin\/cloudflared\stunnel/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string8 = /\\cloudflared\.exe/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string9 = /\\cloudflared\\cmd\\/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string10 = /\\cloudflared\-2023\./ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string11 = /\\cloudflared\-2024\./ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string12 = /07b95428cfb9cb49c2447c2ff9fbc503225d5de7ff70c643f45399fc2f08c48c/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string13 = /0b917a040f43b5b120a3288f76e857203cc52f51c2f78c997d4d0c2da3d0c0c5/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string14 = /0ec73349570f7d8546b9ddfd6b0b409cd622abc133be641bb2a414a2d2b9a21e/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string15 = /17fa4fd9db3006f9aa649b0160770ebb9e9b8a599f6fb5afce83a16a7cb41bdd/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string16 = /1b3e09c31048ec7f2ef06166eb47dcdf0e563ca07b6dcc1318fa6f7db3feb458/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string17 = /2fb6c04c4f95fb8d158af94c137f90ac820716deaf88d8ebec956254e046cb29/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string18 = /33c9fa0bbaca1c4af7cf7c6016cda366612f497d08edd017bced7c617baa7fc2/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string19 = /33e6876bd55c2db13a931cf812feb9cb17c071ab45d3b50c588642b022693cdc/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string20 = /55c11ee0078d85ed35d7df237458e40b6ad687f46fc78b1886f30c197e1683c1/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string21 = /561304bd23f13aa9185257fb0f055e8790dc64e8cf95287e2bfc9fec160eecf8/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string22 = /569b8925a41bd1426fc9f88a4d00aa93da747ed4a5ec1c638678ac62ae1a7114/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string23 = /5868fed5581f3fb186c94b6be63f8b056c571159edb65cc5dafb84553e888d39/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string24 = /62700c23ce8560628d8eb07ab2adcf863ad901c9f631bb45ed4b4f801f35b2a5/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string25 = /6ee5eab9a9aa836ac397746a20afbb671971c6553bf8d6a844ba0a7a8de8447e/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string26 = /9a6f666b2d691d7c6aadd7b854b26cffd76735e9622f3613577b556fe29eb6a1/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string27 = /b3d21940a10fdef5e415ad70331ce257c24fe3bcf7722262302e0421791f87e8/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string28 = /b7e394578b41e9a71857e59d04b7bf582e3d0d15f314ab69f269be474a4b9e1a/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string29 = /ca6ac5c1c1f30675eecf91fe295d703007a754c1b320609ede7aa4783d899e9e/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string30 = /\-\-chown\=nonroot\s\/go\/src\/github\.com\/cloudflare\/cloudflared\/cloudflared\s\/usr\/local\/bin\// nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string31 = /cloudflared\stunnel\s\-\-config\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string32 = /cloudflared\stunnel\screate\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string33 = /cloudflared\stunnel\sinfo\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string34 = /cloudflared\stunnel\slist/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string35 = /cloudflared\stunnel\slogin/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string36 = /cloudflared\stunnel\sroute\sdns\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string37 = /cloudflared\stunnel\sroute\sip\sadd\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string38 = /cloudflared\stunnel\sroute\sip\sshow/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string39 = /cloudflared\stunnel\srun\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string40 = /cloudflared\-amd64\.pkg/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string41 = /cloudflared\-windows\-386\.exe/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string42 = /cloudflared\-windows\-amd64\.exe/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string43 = /cloudflared\-windows\-amd64\.msi/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string44 = /d6c358a2b66fae4f2c9fa4ffa8cd37f6ab9b7d27c83414f70c1d6a210812f0fa/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string45 = /d79111ec8fa3659c887dd4e82f8ce6ff39391de6860ca0c2045469d6ab76a44f/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string46 = /dc76f7c6b506d3ec4a92d9a0cda9678c3cb58a9096587dde15897709c7b23a33/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string47 = /e8118e74c74a62a1d8dc291cb626f46d0056b1284726c2a5d671e20a5e92270c/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string48 = /echo\s\'alias\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string49 = /echo\s\'alias\sfind\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\>\>\s\"\$user\/\.bashrc\"/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string50 = /ed4f5607dbc3fec5d43fbc22fb12a79d8bca07aa60c8733db7f495b7210d631f/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string51 = /fffec1382a3f65ecb8f1ebb2c74e3d7aa57485fb4cff4014aadc10b8e9f3abc8/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string52 = /protocol\-v2\.argotunnel\.com/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string53 = /sc\screate\sCloudflared\sbinPath\=\\/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string54 = /sc\.exe\screate\sCloudflared\sbinPath\=\\/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string55 = /sudo\ssystemctl\sedit\s\-\-full\scloudflared\.service/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string56 = /test\-cloudflare\-tunnel\-cert\-json\.pem/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string57 = /update\.argotunnel\.com/ nocase ascii wide

    condition:
        any of them
}
