rule Lime_RAT
{
    meta:
        description = "Detection patterns for the tool 'Lime-RAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lime-RAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string1 = " /tn LimeRAT-Admin " nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string2 = /\/Lime\-RAT\-.{0,100}\.zip/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string3 = /\/LimeRAT\.exe/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string4 = /\/Lime\-RAT\.git/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string5 = /\/LimeRAT\.v.{0,100}\.zip/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string6 = "/Lime-RAT/releases/download/" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string7 = /\/LimeRAT\-MUSIC\.MP3/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string8 = /\\Lime\-RAT\-.{0,100}\.zip/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string9 = /\\LimeRAT\.exe/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string10 = /\\LimeRAT\.sln/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string11 = /\\LimeRAT\.v.{0,100}\.zip/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string12 = /\\LimeRAT\-MUSIC\.MP3/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string13 = /\\READ\-ME\-NOW\.txt/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string14 = /\>Copyright\s.{0,100}\sNYAN\sCAT\s2018\</ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string15 = /\>LimeRAT\.exe\</ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string16 = "06500a1a2f152b59ceeb662d7bd5bb07175bf45a9c2528b2f6de58394ada4bc5" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string17 = "08a715b0223935b1810024cb32618d84942aebbd10360407b571734ca93749db" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string18 = "0c67fcccaa5ee7a7c0ff82a821e38543b219d7777a07f4394741f9d64f21bf45" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string19 = "116472CE-3924-40EA-90F9-50A1A00D0EC5" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string20 = "14f4e4311f119b7de45d53d0e48d8fe27afdfc1026bab7259ea6191c92c6faa0" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string21 = "1e1e309cc05c6438400f8632b2ac6c375e9d96ebb3b7a2373ff341e4a91fe11e" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string22 = "1E2A1E78-ED0B-414B-A956-86232B1025BE" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string23 = "23f16d48c7f318a3c087efe8ecfc2d7f6563890aae3e96680e7c22660e67c912" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string24 = "2565fc215dd2846177ef9395dfd628b8a99447b4ab83b31eb2c67ca881c3084d" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string25 = "27CF1AE0-5FDE-4B31-A4DA-6FAD1D77351D" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string26 = "2B47F84C-9CA3-47E9-9970-8AF8233A9F12" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string27 = "2d4851e00169abc64ef2432424b1d8d0d41dd4b7ec143fb35d336f647530c82b" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string28 = "2e9447cafdf0506400c263e4656c0a995618be12be9ebbf08cfbc5ea143d328a" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string29 = "363A6DE4-59D9-451B-A4FD-1FE763970E1E" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string30 = "36bab647467333a997dac89001fe066779c64dd73815523b956a44157b542bb1" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string31 = "37b26d324e903117759d48809761ae6e33bc10e4ce50fb06c4980fd42a4cea8a" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string32 = "3891b5f4e423fe98717c69231f6f5ba1db16b1997858f3ecdf1e395bb9640a84" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string33 = "41cdbf8d917fa767fb086bb138e1e0cabd305ccfd22db6759fcda4d769a30a93" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string34 = "433d24896033946acf7ccde0ff7a7d5d0d8608bf1601ac55554d31219dac9995" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string35 = "48a2b0cc57d547c472ef3f49eaf6ebac2db4dea9f59f522a21cd213bea4da5f7" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string36 = "4a4a016032aef2083d5ff676240cdff59697197314a4c66abcf696aa23126de7" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string37 = "4ced09f82c47dc6b5943d5bf74a340113f3f6fc193964e1f9a63591850148aaa" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string38 = "4f3784494848580ecfbb02690d5a22d0501a4bdc3c63fe0fdbdb81b93ae09e37" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string39 = "516387f97a4360654c232915fa5506013fc33f4b4e50e801b4a748070d5ffd3b" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string40 = "55625889-F7BB-4533-9702-DDE98FBB0DDF" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string41 = "5b2ec674-0aa4-4209-94df-b6c995ad59c4" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string42 = "6E25C93C-0985-4D6E-A4C3-89D10F4F4F5F" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string43 = "6f86663035843349077fe85bb9b7b912b4cf9f6334df6e8da098d4750cee871c" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string44 = "733C37D8-858F-44EE-9D17-790F7DE9C040" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string45 = "73bfe881caa5f9e01efe86acede30ffd1a651d77bd7b884e2601064c18c7a215" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string46 = "73ECE052-4218-465D-AA2E-A2D03448BEDD" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string47 = "73EF1630-1208-43C5-9E3F-19A2923875C5" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string48 = "751456c943cbba46078f9443241a2b52f0dfcc47d876ec388213b4cba48ae654" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string49 = "775aff05c1b0ffd703c1b517169770ac9f4aee6a12a30b2b51b5cdb19e7c85c3" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string50 = "8026261f-ac68-4ccf-97b2-3b55b7d6684d" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string51 = "86FC4B74-3B12-4C72-AA6C-084BF98E5E9A" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string52 = "873f95ecce406d76193e9b9b29b8ee05df1089de9f40f47b222e661263e6a56b" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string53 = "8b1f0a69-a930-42e3-9c13-7de0d04a4add" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string54 = "8F71C671-F53C-4F4F-98B9-8B8D3263C0DB" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string55 = "908aaf0590fc3e75a3776ad913ae14c3f328057b8ac0f4135bd1f324a7c1913c" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string56 = "91338f8ea41d0175c0c1cb5a15effe05b35378ec5a3596ca3cca7fee9e3369e9" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string57 = "93520c6aabfdb463c5b74b0409356813b4222190b131664a8343ca0b1b4e7d29" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string58 = "9C30CAE4-6FBE-45CC-90C2-1D739DB92E86" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string59 = "A Slowloris Attack is Already Running" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string60 = "A UDP Attack is Already Running on " nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string61 = "A0E096FB-3AEF-41B5-A67B-BD90D2FEBBFC" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string62 = "a336f517-bca9-465f-8ff8-2756cfd0cad9" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string63 = "ac92d4c6397eb4451095949ac485ef4ec38501d7bb6f475419529ae67e297753" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string64 = "aef6547e-3822-4f96-9708-bcf008129b2b" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string65 = "AF0885E4-9E3B-49CA-9F13-0F869E8BF89D" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string66 = "ARME Attack: Not Running!" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string67 = "b52bf0de684c3d760b7422000c16116af30392da82723239f25a2007e03ee9e4" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string68 = "B672DE08-269D-4AA6-8535-D3BC59BB086B" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string69 = "bc737503f81a21c41b39c2ebcf25949d9012af6efa31d1bf305d0cafe46da136" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string70 = "bec183f1fa76d90ec29cd04ceaf23d80098d71df52ecc378b34260e036b958c7" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string71 = "c0e4afb28f57864b83eb7ae3d5e63a4202decb862fbc5b17a92a51cbd1c469ca" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string72 = "c7eb26b422e1aa10706906aedb442dcc80a5b078e9e83f814f945bb46503a1f4" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string73 = "cd754d69179c52ea3033cbd92addb351f098e231783733919fede70a8e4b2068" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string74 = "CF8C386C-46B2-4F40-BCB1-774C01E72B1C" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string75 = "CFE81801-C2C5-4444-BE67-64EFFEFDCD73" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string76 = /cmd\.exe\s\/c\sping\s0\s\-n\s2\s\&\sdel\s/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string77 = "d081972104ca7a2078d1335415bfc8b4c948bf8e79aa7b6ad70ae4a6d1353c00" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string78 = "D47C706B-152F-46B5-840A-4EBB2CFAFE33" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string79 = "dae0a69520b475e30675c010e3e563fb4b293032353f13ccd73000c697cdc93d" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string80 = "E211C5CD-85F0-48D2-A18F-2E59AD47DDC3" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string81 = "f2894f6ee03703bbd4a7940eb5a29d1521beee7c44d4e2fc095b65b667697365" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string82 = "f3b3b2a5c53aadbd83530a0bf182d75766ebe5f85b0cfde3194b617becb558f5" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string83 = "F56E4E1A-AB7A-4494-ACB9-8757164B0524" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string84 = "fe7fef945a2f5a531f50f6ccef4b40cad832f1e0ffe4d424028379f0318c0c11" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string85 = /HKCU\\Software\\.{0,100}Rans\-MSG/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string86 = /HKCU\\Software\\.{0,100}Rans\-Status/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string87 = /HKEY_CURRENT_USER\\Software\\.{0,100}Rans\-MSG/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string88 = /HKEY_CURRENT_USER\\Software\\.{0,100}Rans\-Status/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string89 = /https\:\/\/pastebin\.com\/raw\/34gqdu7k/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string90 = /https\:\/\/pastebin\.com\/raw\/9kha6nwh/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string91 = /https\:\/\/pastebin\.com\/raw\/DDTVwwbu/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string92 = /https\:\/\/pastebin\.com\/raw\/rGCQC1zq/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string93 = /If\sx\.ProcessName\s\=\s\\"ProcessHacker\\"\s/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string94 = /LimeRAT\sv.{0,100}\// nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string95 = /Lime\-RAT\-87e189781c0aef0e84cabe2f8c2e7d8f5143e594\.zip/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string96 = /New\sPORT\ssystem\.\sYou\sneed\sto\screate\s1\spastebin\sand\sinsert\syou\sports\slike\sthis\s127\.0\.0\.1\:8989\:7878\:5656/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string97 = "NYAN-x-CAT/Lime-RAT" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string98 = /NYANxCAT\@pm\.me/ nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string99 = "Private AttackRunning As Boolean = " nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string100 = "Private HostToAttack As String" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string101 = "U2h1dGRvd24gL2wgL2Y=" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string102 = "U2h1dGRvd24gL3IgL2YgL3QgMDA=" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string103 = "U2h1dGRvd24gL3MgL2YgL3QgMDA=" nocase ascii wide
        // Description: remote administration tool for Windows (RAT)
        // Reference: https://github.com/NYAN-x-CAT/Lime-RAT
        $string104 = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCA=" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
