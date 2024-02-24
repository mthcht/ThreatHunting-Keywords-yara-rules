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
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
        $string9 = /\sset\sxmrig\sType\sSERVICE_WIN32_OWN_PROCESS/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string10 = /\%USERPROFILE\%\\\\nssm\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string11 = /\/xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string12 = /\/xmrig\.exe/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string13 = /\/xmrig\.git/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string14 = /\\c3pool\\\\miner\.bat/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string15 = /\\c3pool\\config\.json/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string16 = /\\WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string17 = /\\xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string18 = /\\xmrig\.exe/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string19 = /\\xmrig\.log/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string20 = /\\xmrig_setup\\/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string21 = /\\xmrig\-6\.20\.0/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string22 = /\\xmrig\-master/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string23 = /\]\sCreating\sc3pool_miner\sservice/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string24 = /\]\sLooking\sfor\sthe\slatest\sversion\sof\sMonero\sminer/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string25 = /\]\sRemoving\sprevious\sc3pool\sminer\s/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string26 = /\]\sRunning\sminer\sin\sthe\sbackground/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string27 = /08384f3f05ad85b2aa935dbd2e46a053cb0001b28bbe593dde2a8c4b822c2a7d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string28 = /0tZG9uYXRlLWxldmVsP/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string29 = /3b5cbf0dddc3ef7e3af7d783baef315bf47be6ce11ff83455a2165befe6711f5/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string30 = /4fe9647d6a8bf4790df0277283f9874385e0cd05f3008406ca5624aba8d78924/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string31 = /5575c76987333427f74263e090910eae45817f0ede6b452d645fd5f9951210c9/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string32 = /5a6e7d5c10789763b0b06442dbc7f723f8ea9aec1402abedf439c6801a8d86f2/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string33 = /99e3e313b62bb8b55e2637fc14a78adb6f33632a3c722486416252e2630cfdf6/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string34 = /C3Pool\smining\ssetup\sscript\sv/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string35 = /C3Pool\/xmrig_setup/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string36 = /c3pool_miner\sservice/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string37 = /c3pool_miner\.bat/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string38 = /c3pool_miner\.service/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string39 = /c3pool_miner\.sh/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string40 = /c3pool_miner\\/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string41 = /cpulimit\s\-e\sxmrig\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string42 = /dd7fef5e3594eb18dd676e550e128d4b64cc5a469ff6954a677dc414265db468/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string43 = /Description\=Monero\sminer\sservice/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string44 = /donate\.ssl\.xmrig\.com/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string45 = /donate\.v2\.xmrig\.com\:3333/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string46 = /donate\.xmrig\.com/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string47 = /Downloading.{0,1000}\%MINER_LOCATION\%/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string48 = /e1ff2208b3786cac801ffb470b9475fbb3ced74eb503bfde7aa7f22af113989d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string49 = /fee\.xmrig\.com/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string50 = /ff6e67d725ee64b4607dc6490a706dc9234c708cff814477de52d3beb781c6a1/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string51 = /github.{0,1000}\/xmrig\/xmrig/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string52 = /gpg_keys\/xmrig\.asc/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string53 = /https\:\/\/c3pool\.com\/\#\// nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string54 = /killall\sxmrig/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string55 = /LS1kb25hdGUtbGV2ZWw9/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string56 = /mining\sin\sbackground\swill\sbe\sstarted\susing\syour\sstartup\sdirectory\sscript\sand\sonly\swork\swhen\syour\sare\slogged\sin\sthis\shost/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string57 = /Mining\swill\shappen\sto\s.{0,1000}\swallet/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string58 = /Monero\sminer\sis\salready\srunning\sin\sthe\sbackground/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
        $string59 = /nssm\sset\sxmrig\sAppNoConsole\s1/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string60 = /offline_miner_setup\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string61 = /randomx\.xmrig\.com/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
        $string62 = /set\sxmrig\sstart/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string63 = /setup\sand\srun\sin\sbackground\sMonero\sCPU\sminer/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string64 = /solo_mine_example\.cmd/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string65 = /src\/xmrig\.cpp/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string66 = /src\\xmrig\.cpp/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string67 = /start\sdoing\sstuff\:\spreparing\sminer/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string68 = /support\@c3pool\.com/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string69 = /WinRing0.{0,1000}WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string70 = /xmrig\-.{0,1000}\-bionic\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string71 = /xmrig\-.{0,1000}\-focal\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string72 = /xmrig\-.{0,1000}\-freebsd\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string73 = /xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string74 = /xmrig\-.{0,1000}\-linux\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string75 = /xmrig\-.{0,1000}\-linux\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string76 = /xmrig\-.{0,1000}\-macos\-arm64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string77 = /xmrig\-.{0,1000}\-macos\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string78 = /xmrig\-.{0,1000}\-msvc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string79 = /xmrig\.exe\s\-/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
        $string80 = /xmrig\.service/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string81 = /xmrig\.tar\.gz/ nocase ascii wide
        // Description: Auto setup scripts and pre-compiled xmr miner for c3pool.com pool
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string82 = /xmrig\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string83 = /xmrminer\.cc/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string84 = /xmrpool\.de/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string85 = /xmrpool\.eu/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string86 = /xmrpool\.eu\:3333/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string87 = /xmrpool\.me/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string88 = /xmrpool\.net/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/C3Pool/xmrig_setup/
        $string89 = /xmrpool\.xyz/ nocase ascii wide

    condition:
        any of them
}
