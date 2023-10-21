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
        $string1 = /\s\-\-coin\s.*\-\-nicehash\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string2 = /\s\-\-coin\=monero/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string3 = /\s\-\-nicehash\s.*\-\-coin\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string4 = /\/xmrig\-.*\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string5 = /\/xmrig\.exe/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string6 = /\/xmrig\.git/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string7 = /\\WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string8 = /\\xmrig\-.*\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string9 = /\\xmrig\.exe/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string10 = /\\xmrig\-6\.20\.0/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string11 = /\\xmrig\-master/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string12 = /08384f3f05ad85b2aa935dbd2e46a053cb0001b28bbe593dde2a8c4b822c2a7d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string13 = /3b5cbf0dddc3ef7e3af7d783baef315bf47be6ce11ff83455a2165befe6711f5/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string14 = /4fe9647d6a8bf4790df0277283f9874385e0cd05f3008406ca5624aba8d78924/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string15 = /5575c76987333427f74263e090910eae45817f0ede6b452d645fd5f9951210c9/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string16 = /5a6e7d5c10789763b0b06442dbc7f723f8ea9aec1402abedf439c6801a8d86f2/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string17 = /99e3e313b62bb8b55e2637fc14a78adb6f33632a3c722486416252e2630cfdf6/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string18 = /dd7fef5e3594eb18dd676e550e128d4b64cc5a469ff6954a677dc414265db468/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string19 = /donate\.v2\.xmrig\.com:3333/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string20 = /e1ff2208b3786cac801ffb470b9475fbb3ced74eb503bfde7aa7f22af113989d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string21 = /ff6e67d725ee64b4607dc6490a706dc9234c708cff814477de52d3beb781c6a1/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string22 = /github.*\/xmrig\/xmrig/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string23 = /gpg_keys\/xmrig\.asc/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string24 = /solo_mine_example\.cmd/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string25 = /src\/xmrig\.cpp/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string26 = /src\\xmrig\.cpp/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string27 = /WinRing0.*WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string28 = /xmrig\-.*\-bionic\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string29 = /xmrig\-.*\-focal\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string30 = /xmrig\-.*\-freebsd\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string31 = /xmrig\-.*\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string32 = /xmrig\-.*\-linux\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string33 = /xmrig\-.*\-linux\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string34 = /xmrig\-.*\-macos\-arm64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string35 = /xmrig\-.*\-macos\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string36 = /xmrig\-.*\-msvc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string37 = /xmrig\.exe\s\-/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string38 = /xmrpool\.eu:3333/ nocase ascii wide

    condition:
        any of them
}