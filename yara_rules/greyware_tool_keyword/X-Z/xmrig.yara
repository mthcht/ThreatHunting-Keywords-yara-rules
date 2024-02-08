rule xmrig
{
    meta:
        description = "Detection patterns for the tool 'xmrig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xmrig"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string1 = /\s\sxmrig\.exe/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string2 = /\sc3pool_miner/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string3 = /\s\-\-coin\s.{0,1000}\-\-nicehash\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string4 = /\s\-\-coin\=monero/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string5 = /\s\-\-config\=.{0,1000}c3pool.{0,1000}config_background\.json/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string6 = /\s\-\-donate\-level\=/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string7 = /\sinstall\sc3pool_miner\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string8 = /\s\-\-nicehash\s.{0,1000}\-\-coin\s/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string9 = /\%USERPROFILE\%\\\\nssm\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string10 = /\/xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string11 = /\/xmrig\.exe/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string12 = /\/xmrig\.git/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string13 = /\\c3pool\\\\miner\.bat/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string14 = /\\c3pool\\config\.json/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string15 = /\\WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string16 = /\\xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string17 = /\\xmrig\.exe/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string18 = /\\xmrig\.log/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string19 = /\\xmrig_setup\\/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string20 = /\\xmrig\-6\.20\.0/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string21 = /\\xmrig\-master/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string22 = /\]\sCreating\sc3pool_miner\sservice/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string23 = /\]\sLooking\sfor\sthe\slatest\sversion\sof\sMonero\sminer/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string24 = /\]\sRemoving\sprevious\sc3pool\sminer\s/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string25 = /\]\sRunning\sminer\sin\sthe\sbackground/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string26 = /08384f3f05ad85b2aa935dbd2e46a053cb0001b28bbe593dde2a8c4b822c2a7d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string27 = /0tZG9uYXRlLWxldmVsP/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string28 = /3b5cbf0dddc3ef7e3af7d783baef315bf47be6ce11ff83455a2165befe6711f5/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string29 = /4fe9647d6a8bf4790df0277283f9874385e0cd05f3008406ca5624aba8d78924/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string30 = /5575c76987333427f74263e090910eae45817f0ede6b452d645fd5f9951210c9/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string31 = /5a6e7d5c10789763b0b06442dbc7f723f8ea9aec1402abedf439c6801a8d86f2/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string32 = /99e3e313b62bb8b55e2637fc14a78adb6f33632a3c722486416252e2630cfdf6/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string33 = /C3Pool\smining\ssetup\sscript\sv/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string34 = /C3Pool\/xmrig_setup/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string35 = /c3pool_miner\sservice/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string36 = /c3pool_miner\.bat/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string37 = /c3pool_miner\.service/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string38 = /c3pool_miner\.sh/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string39 = /c3pool_miner\\/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string40 = /cpulimit\s\-e\sxmrig\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string41 = /dd7fef5e3594eb18dd676e550e128d4b64cc5a469ff6954a677dc414265db468/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string42 = /Description\=Monero\sminer\sservice/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string43 = /donate\.v2\.xmrig\.com\:3333/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string44 = /Downloading.{0,1000}\%MINER_LOCATION\%/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string45 = /e1ff2208b3786cac801ffb470b9475fbb3ced74eb503bfde7aa7f22af113989d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string46 = /ff6e67d725ee64b4607dc6490a706dc9234c708cff814477de52d3beb781c6a1/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string47 = /github.{0,1000}\/xmrig\/xmrig/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string48 = /gpg_keys\/xmrig\.asc/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string49 = /https\:\/\/c3pool\.com\/\#\// nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string50 = /killall\sxmrig/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string51 = /LS1kb25hdGUtbGV2ZWw9/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string52 = /mining\sin\sbackground\swill\sbe\sstarted\susing\syour\sstartup\sdirectory\sscript\sand\sonly\swork\swhen\syour\sare\slogged\sin\sthis\shost/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string53 = /Mining\swill\shappen\sto\s.{0,1000}\swallet/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string54 = /Monero\sminer\sis\salready\srunning\sin\sthe\sbackground/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string55 = /offline_miner_setup\.zip/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string56 = /setup\sand\srun\sin\sbackground\sMonero\sCPU\sminer/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string57 = /solo_mine_example\.cmd/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string58 = /src\/xmrig\.cpp/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string59 = /src\\xmrig\.cpp/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string60 = /start\sdoing\sstuff\:\spreparing\sminer/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string61 = /support\@c3pool\.com/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string62 = /WinRing0.{0,1000}WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string63 = /xmrig\-.{0,1000}\-bionic\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string64 = /xmrig\-.{0,1000}\-focal\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string65 = /xmrig\-.{0,1000}\-freebsd\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string66 = /xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string67 = /xmrig\-.{0,1000}\-linux\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string68 = /xmrig\-.{0,1000}\-linux\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string69 = /xmrig\-.{0,1000}\-macos\-arm64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string70 = /xmrig\-.{0,1000}\-macos\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string71 = /xmrig\-.{0,1000}\-msvc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string72 = /xmrig\.exe\s\-/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string73 = /xmrig\.tar\.gz/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string74 = /xmrig\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string75 = /xmrpool\.eu\:3333/ nocase ascii wide

    condition:
        any of them
}
