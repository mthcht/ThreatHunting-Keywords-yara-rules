rule xmrig
{
    meta:
        description = "Detection patterns for the tool 'xmrig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xmrig"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string1 = /.{0,1000}\s\-\-coin\s.{0,1000}\-\-nicehash\s.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string2 = /.{0,1000}\s\-\-coin\=monero.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string3 = /.{0,1000}\s\-\-nicehash\s.{0,1000}\-\-coin\s.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string4 = /.{0,1000}\/xmrig\-.{0,1000}\-gcc\-win64\.zip.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string5 = /.{0,1000}\/xmrig\.exe.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string6 = /.{0,1000}\/xmrig\.git.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string7 = /.{0,1000}\\WinRing0x64\.sys.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string8 = /.{0,1000}\\xmrig\-.{0,1000}\-gcc\-win64\.zip.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string9 = /.{0,1000}\\xmrig\.exe.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string10 = /.{0,1000}\\xmrig\-6\.20\.0.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string11 = /.{0,1000}\\xmrig\-master.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string12 = /.{0,1000}08384f3f05ad85b2aa935dbd2e46a053cb0001b28bbe593dde2a8c4b822c2a7d.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string13 = /.{0,1000}3b5cbf0dddc3ef7e3af7d783baef315bf47be6ce11ff83455a2165befe6711f5.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string14 = /.{0,1000}4fe9647d6a8bf4790df0277283f9874385e0cd05f3008406ca5624aba8d78924.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string15 = /.{0,1000}5575c76987333427f74263e090910eae45817f0ede6b452d645fd5f9951210c9.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string16 = /.{0,1000}5a6e7d5c10789763b0b06442dbc7f723f8ea9aec1402abedf439c6801a8d86f2.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string17 = /.{0,1000}99e3e313b62bb8b55e2637fc14a78adb6f33632a3c722486416252e2630cfdf6.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string18 = /.{0,1000}dd7fef5e3594eb18dd676e550e128d4b64cc5a469ff6954a677dc414265db468.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string19 = /.{0,1000}donate\.v2\.xmrig\.com:3333.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string20 = /.{0,1000}e1ff2208b3786cac801ffb470b9475fbb3ced74eb503bfde7aa7f22af113989d.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string21 = /.{0,1000}ff6e67d725ee64b4607dc6490a706dc9234c708cff814477de52d3beb781c6a1.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string22 = /.{0,1000}github.{0,1000}\/xmrig\/xmrig.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string23 = /.{0,1000}gpg_keys\/xmrig\.asc.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string24 = /.{0,1000}solo_mine_example\.cmd.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string25 = /.{0,1000}src\/xmrig\.cpp.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string26 = /.{0,1000}src\\xmrig\.cpp.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string27 = /.{0,1000}WinRing0.{0,1000}WinRing0x64\.sys.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string28 = /.{0,1000}xmrig\-.{0,1000}\-bionic\-x64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string29 = /.{0,1000}xmrig\-.{0,1000}\-focal\-x64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string30 = /.{0,1000}xmrig\-.{0,1000}\-freebsd\-static\-x64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string31 = /.{0,1000}xmrig\-.{0,1000}\-gcc\-win64\.zip.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string32 = /.{0,1000}xmrig\-.{0,1000}\-linux\-static\-x64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string33 = /.{0,1000}xmrig\-.{0,1000}\-linux\-x64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string34 = /.{0,1000}xmrig\-.{0,1000}\-macos\-arm64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string35 = /.{0,1000}xmrig\-.{0,1000}\-macos\-x64\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string36 = /.{0,1000}xmrig\-.{0,1000}\-msvc\-win64\.zip.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string37 = /.{0,1000}xmrig\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string38 = /.{0,1000}xmrpool\.eu:3333.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
