rule sliver
{
    meta:
        description = "Detection patterns for the tool 'sliver' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sliver"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string1 = /\sbeacon_win_default/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string2 = /\s\-\-format\sexe\s\s.{0,1000}\s\-\-jitter\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string3 = /\ssliver\ssliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string4 = /\.SliverRPC\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string5 = /\/\.sliver\/logs/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string6 = /\/c2\/tcp\-stager\./ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string7 = /\/c2_test\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string8 = /\/canary\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string9 = /\/evasion\/evasion\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string10 = /\/evasion_linux\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string11 = /\/evasion_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string12 = /\/http\-c2\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string13 = /\/keylogger\.cpp/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string14 = /\/keylogger\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string15 = /\/msf\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string16 = /\/netstat_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string17 = /\/ps_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string18 = /\/server\/c2\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string19 = /\/sliver\.git/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string20 = /\/sliver\.pb\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string21 = /\/sliver\.proto/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string22 = /\/sliver\/evasion\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string23 = /\/sliver\-server/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string24 = /\/spoof\/spoof_windows\./ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string25 = /\/srdi\-shellcode\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string26 = /\/syscalls\/syscalls_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string27 = /00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string28 = /1f25c454ae331c582fbdb7af8a9839785a795b06a6649d92484b79565f7174ae/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string29 = /3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string30 = /amsi\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string31 = /armory\sinstall\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string32 = /armory\sinstall\s\.net\-execute/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string33 = /armory\sinstall\s\.net\-pivot/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string34 = /armory\sinstall\s\.net\-recon/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string35 = /armory\sinstall\ssituational\-awareness/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string36 = /armory\sinstall\swindows\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string37 = /armory\sinstall\swindows\-pivot/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string38 = /B64_ENCODED_PAYLOAD_UUID/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string39 = /BishopFox\/sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string40 = /cursed\schrome/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string41 = /cursed\scookies/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string42 = /etw\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string43 = /generate\sbeacon\s\-\-mtls\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string44 = /generate\s\-\-http\shttp/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string45 = /generate\s\-\-mtls\s.{0,1000}\s\-\-os\swindows\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string46 = /generate\s\-\-mtls\s.{0,1000}\s\-\-save\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string47 = /generate\s\-\-tcp\-pivot\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string48 = /generate\/canaries\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string49 = /generate\/implants\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string50 = /github\.com\/bishopfox\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string51 = /http\-c2_test\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string52 = /implant\/sliver\// nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string53 = /inject\-amsi\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string54 = /inject\-etw\-bypass/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string55 = /install\sc2tc\-domaininfo/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string56 = /kick\-operator\s\-n\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string57 = /leaky\/leakbuf\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string58 = /new\-operator\s\-\-name\s.{0,1000}\s\-\-lhost\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string59 = /pivots\/named\-pipe_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string60 = /portfwd\sadd\s\-\-bind\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string61 = /portfwd\sadd\s\-r\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string62 = /priv\/priv_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string63 = /procdump\/dump_windows\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string64 = /profiles\sgenerate\s\-\-save\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string65 = /profiles\snew\sbeacon\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string66 = /profiles\snew\s\-\-mtls\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string67 = /raw_keylogger\.tar\.gz/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string68 = /rpc\-backdoor\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string69 = /rpc\-beacons\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string70 = /rpc\-hijack\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string71 = /rpc\-kill\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string72 = /rpc\-msf\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string73 = /rpc\-shellcode\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string74 = /silver.{0,1000}\/beacon\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string75 = /silver.{0,1000}implant\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string76 = /Sliver\sC2\sSession/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string77 = /sliver\.service/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string78 = /sliver\.sh\/install/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string79 = /sliver\/\.sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string80 = /sliver\:sliver/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string81 = /sliver_pcap_parser\.py/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string82 = /sliver\-client_linux/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string83 = /sliver\-client_macos/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string84 = /sliver\-client_windows\.exe/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string85 = /sliver\-dns/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string86 = /SliverKeylogger/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string87 = /sliverpb/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string88 = /sliver\-server\sdaemon/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string89 = /sliver\-server\./ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string90 = /StageListenerCmd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string91 = /testing.{0,1000}\stesting.{0,1000}\s1.{0,1000}\s2.{0,1000}\s3\s/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string92 = /UseBeaconCmd/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string93 = /raw_keylogger\s/ nocase ascii wide

    condition:
        any of them
}
