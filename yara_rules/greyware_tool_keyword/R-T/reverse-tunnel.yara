rule reverse_tunnel
{
    meta:
        description = "Detection patterns for the tool 'reverse-tunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-tunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string1 = /\srtun\-server\-windows\-amd64\.exe/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string2 = /\srtun\-windows\-amd64\.exe/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string3 = /\sStarting\stunneling\sserver/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string4 = /\/reverse\-tunnel\.git/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string5 = /\/reverse\-tunnel\/agent\/cmd/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string6 = /\/reverse\-tunnel\/server\/service/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string7 = /\/rtun\-freebsd\-amd64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string8 = /\/rtun\-linux\-amd64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string9 = /\/rtun\-linux\-arm64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string10 = /\/rtun\-mac\-amd64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string11 = /\/rtun\-server\-freebsd\-amd64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string12 = /\/rtun\-server\-linux\-amd64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string13 = /\/rtun\-server\-linux\-arm64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string14 = /\/rtun\-server\-mac\-amd64/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string15 = /\/rtun\-server\-windows\-amd64\.exe/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string16 = /\/rtun\-windows\-amd64\.exe/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string17 = /\\rtun\-server\-windows\-amd64\.exe/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string18 = /\\rtun\-windows\-amd64\.exe/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string19 = /0f5c329fa1e4abd3d1d2fbbd493d0dcf419bc33e1aa809ed55500481ed2ebe65/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string20 = /14d29e0f977fb74a925c9c2cab1ef3ed34eb6b35345b0af1645a64f6b85040f8/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string21 = /19529823b5d0e8b0c2a4cf5e67b825254efbd7568b7d6b204a220e684e3787d7/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string22 = /1ccedb3262e89f8d841a6c6b3ea5e8c5ef8fb42779168e5cc47ba1674be930f1/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string23 = /2e28d91e35ca1009d77fc67d36553730e785333ffc14cb8af621113571bd730b/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string24 = /2e4ce6b3a2e7019459a3f6cad24e07ee614c800a9d5b29c3d83f50fd758d1a93/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string25 = /397ac6bd1ffe2d8baf3c8e41307bb36339fa0f7a97e61b614d25ab85cb3b90a7/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string26 = /3b76d79a32202f1cdbae1e5ed949ee7a75f373a9280fbdfd15a6cc4490a1b595/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string27 = /3e62062061ddd7a0974eb2f6106dc96d3c54f95f41121ff355de12d5a23e2624/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string28 = /411b16657e992717f0eb9ac77b2a5468e23afcc8747bdabba4bcdfc008c845e7/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string29 = /512fba960ac745dbb62576225ee9dd7f65bf83261c8d1364f50101c8e3fd55bf/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string30 = /5e47aac7b50d8ac6ce9ebba6c28ca58ef1332493fba47ab47ec1d2da61c7f6e2/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string31 = /6ab324b655ea1c39c3c8fb5709f322f0c468a203411fbbcb460b36ee0fc1d835/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string32 = /6f94077fc6f9092d9e9282bee1588e70aaf70ad90407e2bd164c38325249af5e/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string33 = /774dbc75e046096a7a18dbcef9353543db74312e9656ff4017d7f41c778be2fb/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string34 = /793e227ee3a811a143e303909645a874c8db144cf6b48f480411efb2fdd44904/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string35 = /8fd62fc653cef0bf765a71cf20a917c8440689e9f5ff77e95a5fea7be6818c66/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string36 = /955854f00a41ee91d047e520aa445035d881f9cb214de1ed49fac829e1caf829/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string37 = /a522a8bfbf83bf52cde85edb32577d6b9acddac6e3a432726f659ae7dd5a6a96/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string38 = /a79a4c3ae4ecd33b7c078631d3424137ff332d7897ecd6e9ddee28df138a0064/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string39 = /a8ebccf2cc342e1b5154989cd784691b5740a7f3df77cd8adb785f67384a93de/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string40 = /ba65a4a428b16812cfade65b50138e0b865496a637bdf5dad7993bf3907cdd60/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string41 = /d66a79fcbac667d28014c15003770a35bd941c346e87fb8e4e1b7fd02c3291c9/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string42 = /d71bbdd588cd4f1507ea794ed63be80a7cb3bbb1d30430150dd8800adec83fd5/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string43 = /d7eceeb90b1e75b17c42c6cef5b42e0ef1dc615efba9424bafce718304c7ee43/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string44 = /dec51bba37da4ecf4df8994cb21931fdfcc4f661c362cb8392f44229d42ef337/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string45 = /e6c9ef3c9ee804ca3bed5f13f5e179f9ef16b7b2513cdfc33974902faa0f7516/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string46 = /e717e4a46f338480838e760a05b7a628ccca57b0d4d705a67359bf9481fa58ae/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string47 = /ef77dea20926b6f460844b5a51fd0d238976a1dba89f20f0fccff96712ad9df8/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string48 = /f865ac0b99a90f54ce67bbabb2e57226a5c61f58e7a867598a3d54fdfee895ee/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string49 = /f99a0080be86f97331ea300f2a4f448097c5ae39100b15202c89fc91024b215e/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string50 = /snsinfu\/reverse\-tunnel/ nocase ascii wide
        // Description: rtun is a tool for exposing TCP and UDP ports to the Internet via a public gateway server. You can expose ssh and mosh server on a machine behind firewall and NAT.
        // Reference: https://github.com/snsinfu/reverse-tunnel
        $string51 = /Tunneling\sremote\sconnection\sfrom\s.{0,1000}\sto\s/ nocase ascii wide

    condition:
        any of them
}
