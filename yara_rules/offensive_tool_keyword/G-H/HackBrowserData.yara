rule HackBrowserData
{
    meta:
        description = "Detection patterns for the tool 'HackBrowserData' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HackBrowserData"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string1 = /\.exe\s\-b\s.{0,1000}\s\-p\s\'C\:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User\sData\\Default\'/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string2 = /\.exe\s\-b\sall\s\-f\sjson\s\-\-dir\sresults\s\-cc/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string3 = /\/chrome_creditcard\.csv/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string4 = /\/chrome_creditcard\.json/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string5 = /\/chrome_password\.csv/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string6 = /\/chrome_password\.json/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string7 = /\/HackBrowserData/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string8 = /\/HackBrowserData\.git/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string9 = /\/hack\-browser\-data\-linux\-386\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string10 = /\/hack\-browser\-data\-linux\-amd64\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string11 = /\/hack\-browser\-data\-linux\-arm\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string12 = /\/hack\-browser\-data\-linux\-arm64\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string13 = /\/hack\-browser\-data\-osx\-64bit\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string14 = /\/hack\-browser\-data\-windows\-32bit\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string15 = /\/hack\-browser\-data\-windows\-64bit\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string16 = /\\chrome_creditcard\.csv/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string17 = /\\chrome_creditcard\.json/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string18 = /\\chrome_password\.csv/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string19 = /\\chrome_password\.json/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string20 = /\\hack\-browser\-data\-linux\-386\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string21 = /\\hack\-browser\-data\-linux\-amd64\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string22 = /\\hack\-browser\-data\-linux\-arm\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string23 = /\\hack\-browser\-data\-linux\-arm64\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string24 = /\\hack\-browser\-data\-osx\-64bit\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string25 = /\\hack\-browser\-data\-windows\-32bit\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string26 = /\\hack\-browser\-data\-windows\-64bit\.zip/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string27 = /0033346a10079dc04814e00f7717d40f104b309c5b8a0a8956fd871e305b8ae4/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string28 = /036f633201389badc16397101c718b3b6dea0ef726171e0448157129faa389b9/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string29 = /04318d1196862e1078e431e6d59dfeafba540d0369346dcfc6432a30d9c37e54/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string30 = /04c8a0077ac2c4db41e2bba0b7052fb1d0b492a6e301853b3e189223a989e1c7/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string31 = /0796f9b079afb6b3a36ab11ae96bcad44364429fd9bceee074225736507bb14e/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string32 = /0bef08167ba7fbe62a07368279b1b6d8450cdb04696eb9abf18b02be519abd99/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string33 = /1302e8b96f9a4f7230cd751f740305bb98231e4b9cb5ebeb68ba0d4fd71231b6/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string34 = /164425759daa52e1a44001421120e2f616f08614239f5231be763061c6e56892/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string35 = /1b2b249d1cc2d53c4d21bfbd0a1ab7548e2ac369b13bdba538c76ba7813ce595/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string36 = /1b46ed14bbd4feb50be61fb1f3535adbca65d4927a3f14eaa19202deebe29041/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string37 = /1b609698b6ff63a7b10bc9b656a698ce57b1995ee1f8894673d4e58e16e2a93c/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string38 = /1c50edff472ca0901cc9f483e21487dc2c8734e91a10f9426fac07bfea048277/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string39 = /1cb076b6d5b6cb781a5af9b1211d2309840a6b47c4998b802fb8667771548e17/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string40 = /1ec6f023ad651375efd66ae2a21f7609ed29b9fdfe725304bbaf219f5876350d/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string41 = /1f28b88a26c282842ad06aa962b62120f44bbecece84394c2498e784ceafa526/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string42 = /2145f05e4090b6b0ef64720547ca85d7c4960b6fd91202a524f99ed832c0b54b/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string43 = /21c6e03b7a1e354d984e88080e3843f7fbd71df02fc91df92f99d4f8a11c5ea0/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string44 = /221ac33db7069624a6840a57b5adb7ed34ee49f911b200aa4c5d15cea7ebaf69/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string45 = /22f3cfc7bd97c20e7a313b9710a41426f42fcbf4bb6dbe108a36c92c328737a4/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string46 = /2305237cb1b9b2320b7e62741e4a8835777462f59c9584dbcfd0672e6f2c8150/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string47 = /25a3a725cec379cb70766bcc8ba6a87dba12de35f73c5e0439e2673e6840dc9a/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string48 = /26fcb5597cb7d3eddd3bb24440de6555b3d34af4c9a3874b71fa27aff18ea3d5/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string49 = /28b5a291efc22edff0f84eec3720d1513151a2a551b09896a7fff354cba5aaff/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string50 = /2e3bc20ce205875bea72dc1aceafc75307c0ed033d7e11846d97ca30ab3852ee/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string51 = /318c7820d295ab78772ec8424dfc4e0a9619d81ea56ab4df81236f1a42707c97/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string52 = /32db0ad0f6cdbdd9481c02062ed78535bd65185331a7ae6b198e3e5eb6b5a59a/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string53 = /3342b13f536e40d34e2a0155667854ddd3904c193db870c7c759365530b2ae82/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string54 = /34db2170c5e68bb656c1bc57c0932f4b89c10133d478e9459b36641da5a47c4e/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string55 = /3532e7da204a5242b3ee2a3081cc68f7cd3728d45bbcbc582c077472bba4a7f5/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string56 = /362a1076dc1f77532a07c12db0b3ce368eac2b15d1cfc8afa1a1a735ac25e430/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string57 = /395cb1f243d7c705459a5c7c931b48617a39ca9e89b04f4c9759f25364cfe371/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string58 = /3a14a252eb81351a4b9b204b416e17ced7f2af340e2b635c149cf53bf1be2732/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string59 = /3c1785d7fa372507bd98842717b7bc12744b15f7a7a97856790f664561c959c2/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string60 = /3d9e27be3e47c7e35f0a8b3cc989ec9fe4915f323518fc380a64c080a752a7a7/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string61 = /3f731e2fb08a9113084dcbffa31890d2b42c817f8ae6da445502130b7e5f512b/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string62 = /4280a088866261d65bcfb3409133327b35626000c4c5b838d50c0d650baa8a62/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string63 = /4334cdefe34ccba3224c79ed27d7feb1980e8f138a6dd0f993f6f830caa2476b/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string64 = /456a99ccb18c638425add933b1ae1fcef59cb064aa97dc0be231d16c35bddff0/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string65 = /4b4a532b9efe70d220a086a839b59bf80d00368d3f821fb7f81f92eeb9ba3edc/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string66 = /4bbce282aa26a449030a398e4ff5e980137a05d91f205037ac1bb297f3c36513/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string67 = /4bc67e5404e070bce9952de907f957cb0451a92c7a0c468a73755b2947f344c6/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string68 = /4c9e1588af0f951fbb311cd29bac8ce03c7d00175d5ef6747bab9ef127abc0c4/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string69 = /4d710fdd6e18bf8ad16847a9e03cf858b20eaeec3e6b8fe9ac1b29eb36883892/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string70 = /4e19296bcc9b552e7993c02d573a1a5102e0733873aced32809d68c4d0b8428d/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string71 = /4e50d7d853d7b14ecbaa3ec881d83deac55fb19d4934a6f7ab0cb887b7dbf991/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string72 = /4e6ce0dc8e2b945807e72bc1006cc3ed126542ee95395ccbf973a47cc8b7f04a/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string73 = /519637a04042d8869004121a6e80c35aa2b2370647de9604cbf3ac4eae79424b/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string74 = /52c54e36cc278993f45d25a56307059f6b6682d802045eaf8eab92ae577eb2e4/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string75 = /56f3c70dd9cb4be15fb429491245d75ce48a4cb9d8877f2be6e2493673674606/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string76 = /59395105f688ef8c35cf2061928c2cb7f2f5d748518ca9ebfa5ee14a2461915e/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string77 = /610f948ee1af2ac334186ca21a3bea4d819a45fee51c2753fe1cd0bb8cc30d1d/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string78 = /63e9c4ad28c4ee5fd63bee6124590a0edb6c7dc4b20d1b4f6aefdb53f5b94a1a/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string79 = /646698ef7a2a2cf03c2068c8e1c8b2f8fc18128b6027100c45acfe18b5c6d177/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string80 = /64e8b1efc560e837ac87e1fe231b92781d5eb9dfc3688d10fd38ed32f5556640/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string81 = /651e286fdf6d57e43df7aeb51d819999ecc28621bdefb834a5ef57d41dcf7336/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string82 = /6646a6c4e3006b90ff7009eb28cd9d5ff182d7f4d8465dbe63357a8c054257bb/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string83 = /67f6f13cd32457711eb5171e7f87942319edd25e5463ac770e7666d71b1382b7/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string84 = /6a0b2e5491caa977cc4efcea1a90b67480126b0d3148d1436add939bfbe785d5/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string85 = /6b1017d1325f9f981edbaf071defdda45e26af30eb2a6819c039a6a17e8a14c7/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string86 = /6d5aef94f94fcf9b0987102f2b436e37f173e9638b08d1cd45d14132071617db/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string87 = /6d6a190059cb9ace0b4e16aace82f752ae57df9b36db03508acb3bb4fabe4d05/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string88 = /716ba53b9245b9f98cd68f191e20451f7a6d54864486051e8ce1f08132df97e4/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string89 = /738dd06fea4b4b507c0438eac77c8ed3267ed9617b51c565ea05f21529999164/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string90 = /746c0a01b163c57f729738cfe39c1c83d0b938aa48f07d1f866c1b8adaec4aa0/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string91 = /74c63668a8b03c046dcb1293ccffd2e0f7b4dd22210a4faff3d29a0db5761d20/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string92 = /77b681a78da38b33f408ccdc747438550186a348f670d2faaa05ef75f9337973/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string93 = /7b41987489d49340783b4b6604899143c2c6c67f66708d80df217c509ff8b4dd/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string94 = /7bcebf955c725d8d50ee161d523e06891dadb93fb98fc9fe74a1056c374c767c/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string95 = /7c6036ed3f0b67af1cc73941987fbe7884789264691d05604e8a5e8b3cd9b5a1/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string96 = /7f73a800a012c6b522a92074901c256d947a7a080bc2efb3da65784b2f50a054/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string97 = /7fe5b73ee8105622ab74be4fae9f5f0a9b2a8b496770d84b58a7c0ce8a457551/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string98 = /8019f095c7cf482767df31cd411cc53c4e30a23c599aa9381391326a6e7c6304/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string99 = /83dd7c7738c5409a2f50d06f38eb82be09a232794771c87d81080220e6ab5195/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string100 = /84d6bf44ebad6338855d9e4abafaed229c778a645c18e1bd5a343bf930c75110/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string101 = /85929c3b220867064975eb8a6ca57cd5b22b801e3f805e653f298f3e6cebe6a3/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string102 = /863f8f71cce6acffa596561047c4592087b08a66438bd5500a4053169f31a9ce/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string103 = /87623bf79b1d7bbd0e66a6e6c5e534afdef66debdd5ff363648cb5482e7a6ed7/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string104 = /889a7d961d4e847d37d3019ccd1625a335d2e2d18c6fb1ec1d41aa4df679f553/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string105 = /8909f956ab41ad565935485870d05b47db8482c703aa7ea142ef1eff310e8b89/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string106 = /89e27312c55e98af1c2f4882a53b08abc4a54fc8d6c09959447f2444b3ccece1/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string107 = /8a274c53950fe680f5b5eb76594aa0b30facdf93187277d03653334a5224f6a0/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string108 = /8b43f966bd55fe366e37e1974cdbe61cb01618c4df5298df928de0e2599b6050/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string109 = /8c1e9d935d60c007bd43d10b206cd229c851b654562e6bb93ce009481d827afb/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string110 = /8c6291f935445adc486c03da6169b471fc2436d5b594972b14eaeb37350aa3ef/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string111 = /8ebbf29735fb137a1de8df693e7762685ecf873e5b83fc927cd561e170c275bd/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string112 = /93d8276129ccc984a4063772029e8db9002dfd82028c24864b5767cd6c7ce17d/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string113 = /94ebb5f2aef9398a08a40e352a09bf6f83e01c0a666e3adb017636af3e0bee12/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string114 = /96cff9ea19fa5ef9e119e9b00f67d9744efa55bd15df77248201ac09050d8322/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string115 = /970c07b17ca0d662ea2c5b0958efcf8e28053ee8d2a2c78436cce460413933b1/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string116 = /985ac7064c18852f34f9243d5d51703fca8e5540efe1d01a259640b5798c2724/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string117 = /9a193c64e8f1aceb242bf7435f04279b140e19273a2c7c0ff99561fd7abd9652/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string118 = /9a1f3ecde8800a00c549fbfa3cf55acbb811fec282d2bea19b27cca9bfe8b947/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string119 = /9ab8a5bbfcdac675219e4415487b8a34270102bb34089609378abe8ea071d13a/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string120 = /9de97ca3add57fbe16c2752b22478d49eacdd3d8f1c032bb43792a83ca92e5ca/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string121 = /a11f916dc20d775bd4961ae27388d2ac5a6613a45e58589040aacd8e70042a23/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string122 = /a5553553f4c9056cff908df93f4dd7f498a9ce180048d1331ed00028d644ea00/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string123 = /a58ef464df86f0f3dfab3123cae2fbfd6cb86b707f9dfa4a281ea0e9a40a858d/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string124 = /a74524600479028cf1f6231ddfa1e701c98f333667461a3b20124ee3b36bd650/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string125 = /a7aa95075ecb1e4b2201ac1962eac88639e816ebf94c0d08b2bd5da274a981db/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string126 = /a88a0af4e583fbae14ad5003c85f29949b720db848e373668924880369fa8fbd/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string127 = /a9830d372873174b5e855d0ba4b0f14912e007657bfe0bdcddae7f10e0ea7a03/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string128 = /ac237c0f9cc970822dee74c4251b50a87c637af3d8b087ceb5162aaee4b67381/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string129 = /ac24f9111a5e72c85f2b32ce3c09f46814363c98383be1e972839d89b1a3d18c/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string130 = /b09adb4d79fd71cba1d5c51c514d4a10e08f92fed9eca3637a2f68d6c2f8e835/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string131 = /b264796db3513dbee419561215cb7c5863d70088dd5e8286829801bc72c27d0b/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string132 = /b2a02c9a9eb70c92a0af31a0485b345375b545a639f01e3cba8bdb5b09149662/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string133 = /b5b0c796fe213a7f4a840d46a10ad4d36eb26521c19e026ae5f46b17f390b77a/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string134 = /b68e24dd90e163f0048746d1c49d16f82e62608ac441df90c5f18b0b79b8b879/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string135 = /ba64c77b96c7de18007ca116ca8c8f93c3bba3cdc631e1a041e9d0afb46ae989/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string136 = /baf93de7d2d00045f677a77eeb729753c930f4d0be125a6f32db82cfe7592846/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string137 = /c672719ea7d0abfbf7b69605b975d697afeb5cad770e9cb68e57ee18d7e598d1/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string138 = /ca698d8da51b0df3302f8e8593f3fceecf8c513d92a73bc3b585363a4d09bc61/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string139 = /cbec6150e83403631fe741f0c50e516170279645c246638b0148e1b87c0848e7/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string140 = /ccb9d0f9cd95c1665d9646771f7e21af912106f7cc7541c338552b66ca0df512/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string141 = /ce4abd249e1f6497549ca7a2e814c8232f42597ce8b02f77fd3dde31a723a501/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string142 = /ce8cdc354e0ff5b4aa329e1ef3e55aaabfcb1a592c697b327e93b59f5ae9a217/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string143 = /d169a3057a62c9cc881c25e8f78c915c2c967a7c537a270239c87a1cad44b76e/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string144 = /d1e9bbf0fb621285de6ea7b4c2b3f8dc2a15d0e51639eafb8f2fb8aca47054e0/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string145 = /d21f5b2cbd06f1f679bcc65b7d40fc203c1f7008dac678f7edf14577d8c2246f/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string146 = /d328400cdc424aa3a54ad23f20979aca1324d1de62e28a69c18819671e597b03/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string147 = /d42056fad9278acecf2a979acd6aa24bd1e757c8429a424b245dbc0a39bde9a2/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string148 = /d7935f00dbd30fe83bd877aa2e841b8aa0c0ded7f2867b677a6e24d3fd3daaba/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string149 = /d7a74608cdc46702dca5c703ad3bbc40c8b97ce6cea40695b7499987a70a9331/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string150 = /d9b9491fbe838aa7d97c46ef81f42c9c9748aabec0697d9abde6ddd6b464c1eb/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string151 = /dadf9d853d94eb24a563cc2bba0c5539c8e92bf6340ac823f00af44b25a5a148/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string152 = /db65c744d5de72d0e727cf670e992aeec6e4e195298e71f22c095eb63df4f923/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string153 = /dc95d92765b7ff96b8311920bfc939a9f234e961efc7c8fa4effe5d39ec13ea1/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string154 = /dd09d2d4ba9ffc6ddc939ede8a494a4aaadccdcfa441576499f1b85d8580f97e/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string155 = /de3a20c75f66c663508436a2a3d049987158976535bb5e5eaa63823dbf6d7e3f/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string156 = /deced84e656eb8ae4d4c57dfea5d0a74b558f5975621a9ae0d25d59d3c550f4f/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string157 = /e0e4200ebb8381797450c5f7da031a1c389c31c3351370daa1b53c715ea07097/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string158 = /e7ce68e94b4b3a3f8ba4e660edd00c794af6d158ce6f993d74d9732cfd83f2c7/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string159 = /ef644b1554eb1561456e7e20b136f4fff16c3a02e821d06da3c3a6dd9aa168bc/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string160 = /ef98c122f795f0c0d7719fc02825df198cdd373ba56e17940d28ffaf13f5fce3/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string161 = /f253b430b9d2dafe0e67a9974e7a806f21c6589c02aed1cdc595d23fe619f492/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string162 = /f372c2d7604f63043b3ffe8d382b6ac45a719bd125a7e7f13691eb223a8db509/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string163 = /f80eda59c7a3c13a369756294727a931e983916bdbd1b9b0b4e010b84d6ce450/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string164 = /f8240f1a0ce4d4a1ec3e880c7bc56fee6c3c790d48ec20bc35ac5ffad8861798/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string165 = /fa220acf9aa2972ac3ed01e854cfa219e017a533c0e629740b03151cf962dd91/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string166 = /fb120f28b0e4d979b147635e9549362bb12e35d4b24a345fc5f208dd089ae4cb/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string167 = /fb93ead7778fa1593e651220420a86f63afcf3fdfc673f19c801b5de71ab5ac8/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string168 = /fc97c521e6bd003e20bd27d2de03f954e9f557167a015bcbe3322b60542fca4e/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string169 = /fe06cf10cad44865c87cb7a2eef5d3b7614309ce016389add8260f19f16d770b/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string170 = /fed9b7e5d2f1b284d5f757fcf95f97d8deb08b794d2764b0318cde7f95cc0496/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string171 = /hack\-browser\-data\.exe/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string172 = /moonD4rk\/HackBrowserData/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string173 = /Reflective\-HackBrowserData/ nocase ascii wide
        // Description: Decrypt passwords/cookies/history/bookmarks from the browser
        // Reference: https://github.com/moonD4rk/HackBrowserData
        $string174 = /Sharp\-HackBrowserData/ nocase ascii wide

    condition:
        any of them
}
