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
        $string1 = /.{0,1000}\sbeacon_win_default.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string2 = /.{0,1000}\s\-\-format\sexe\s\s.{0,1000}\s\-\-jitter\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string3 = /.{0,1000}\ssliver\ssliver.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string4 = /.{0,1000}\.SliverRPC\/.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string5 = /.{0,1000}\/\.sliver\/logs.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string6 = /.{0,1000}\/c2\/tcp\-stager\..{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string7 = /.{0,1000}\/c2_test\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string8 = /.{0,1000}\/canary\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string9 = /.{0,1000}\/evasion\/evasion\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string10 = /.{0,1000}\/evasion_linux\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string11 = /.{0,1000}\/evasion_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string12 = /.{0,1000}\/http\-c2\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string13 = /.{0,1000}\/keylogger\.cpp.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string14 = /.{0,1000}\/keylogger\.exe.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string15 = /.{0,1000}\/msf\.go/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string16 = /.{0,1000}\/netstat_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string17 = /.{0,1000}\/ps_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string18 = /.{0,1000}\/server\/c2\/.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string19 = /.{0,1000}\/sliver\.git.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string20 = /.{0,1000}\/sliver\.pb\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string21 = /.{0,1000}\/sliver\.proto.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string22 = /.{0,1000}\/sliver\/evasion\/.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string23 = /.{0,1000}\/sliver\-server.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string24 = /.{0,1000}\/spoof\/spoof_windows\..{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string25 = /.{0,1000}\/srdi\-shellcode\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string26 = /.{0,1000}\/syscalls\/syscalls_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string27 = /.{0,1000}00000000000000000043d43d00043de2a97eabb398317329f027c66e4c1b01.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string28 = /.{0,1000}1f25c454ae331c582fbdb7af8a9839785a795b06a6649d92484b79565f7174ae.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string29 = /.{0,1000}3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string30 = /.{0,1000}amsi\-bypass.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string31 = /.{0,1000}armory\sinstall\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string32 = /.{0,1000}armory\sinstall\s\.net\-execute.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string33 = /.{0,1000}armory\sinstall\s\.net\-pivot.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string34 = /.{0,1000}armory\sinstall\s\.net\-recon.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string35 = /.{0,1000}armory\sinstall\ssituational\-awareness.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string36 = /.{0,1000}armory\sinstall\swindows\-bypass.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string37 = /.{0,1000}armory\sinstall\swindows\-pivot.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string38 = /.{0,1000}B64_ENCODED_PAYLOAD_UUID.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string39 = /.{0,1000}BishopFox\/sliver.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string40 = /.{0,1000}cursed\schrome/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string41 = /.{0,1000}cursed\scookies/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string42 = /.{0,1000}etw\-bypass.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string43 = /.{0,1000}generate\sbeacon\s\-\-mtls\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string44 = /.{0,1000}generate\s\-\-http\shttp.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string45 = /.{0,1000}generate\s\-\-mtls\s.{0,1000}\s\-\-os\swindows\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string46 = /.{0,1000}generate\s\-\-mtls\s.{0,1000}\s\-\-save\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string47 = /.{0,1000}generate\s\-\-tcp\-pivot\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string48 = /.{0,1000}generate\/canaries\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string49 = /.{0,1000}generate\/implants\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string50 = /.{0,1000}github\.com\/bishopfox\/.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string51 = /.{0,1000}http\-c2_test\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string52 = /.{0,1000}implant\/sliver\/.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string53 = /.{0,1000}inject\-amsi\-bypass.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string54 = /.{0,1000}inject\-etw\-bypass.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string55 = /.{0,1000}install\sc2tc\-domaininfo.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string56 = /.{0,1000}kick\-operator\s\-n\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string57 = /.{0,1000}leaky\/leakbuf\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string58 = /.{0,1000}new\-operator\s\-\-name\s.{0,1000}\s\-\-lhost\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string59 = /.{0,1000}pivots\/named\-pipe_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string60 = /.{0,1000}portfwd\sadd\s\-\-bind\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string61 = /.{0,1000}portfwd\sadd\s\-r\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string62 = /.{0,1000}priv\/priv_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string63 = /.{0,1000}procdump\/dump_windows\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string64 = /.{0,1000}profiles\sgenerate\s\-\-save\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string65 = /.{0,1000}profiles\snew\sbeacon\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string66 = /.{0,1000}profiles\snew\s\-\-mtls\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string67 = /.{0,1000}raw_keylogger\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string68 = /.{0,1000}rpc\-backdoor\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string69 = /.{0,1000}rpc\-beacons\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string70 = /.{0,1000}rpc\-hijack\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string71 = /.{0,1000}rpc\-kill\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string72 = /.{0,1000}rpc\-msf\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string73 = /.{0,1000}rpc\-shellcode\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string74 = /.{0,1000}silver.{0,1000}\/beacon\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string75 = /.{0,1000}silver.{0,1000}implant\.go.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string76 = /.{0,1000}Sliver\sC2\sSession.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string77 = /.{0,1000}sliver\.service.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string78 = /.{0,1000}sliver\.sh\/install.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string79 = /.{0,1000}sliver\/\.sliver.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string80 = /.{0,1000}sliver:sliver.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string81 = /.{0,1000}sliver_pcap_parser\.py.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string82 = /.{0,1000}sliver\-client_linux.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string83 = /.{0,1000}sliver\-client_macos.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string84 = /.{0,1000}sliver\-client_windows\.exe.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string85 = /.{0,1000}sliver\-dns.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string86 = /.{0,1000}SliverKeylogger.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string87 = /.{0,1000}sliverpb.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string88 = /.{0,1000}sliver\-server\sdaemon.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string89 = /.{0,1000}sliver\-server\..{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string90 = /.{0,1000}StageListenerCmd.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string91 = /.{0,1000}testing.{0,1000}\stesting.{0,1000}\s1.{0,1000}\s2.{0,1000}\s3\s.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string92 = /.{0,1000}UseBeaconCmd.{0,1000}/ nocase ascii wide
        // Description: Sliver is an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/trustedsec/SliverKeylogger
        $string93 = /raw_keylogger\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
