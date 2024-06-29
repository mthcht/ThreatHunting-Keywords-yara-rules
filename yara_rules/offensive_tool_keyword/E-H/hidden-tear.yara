rule hidden_tear
{
    meta:
        description = "Detection patterns for the tool 'hidden-tear' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hidden-tear"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string1 = /\"dsdoskdosk837928hduijfh\"/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string2 = /\/hidden\-tear\.exe/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string3 = /\/hidden\-tear\.git/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string4 = /\/HiddenTear\.zip/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string5 = /\/hidden\-tear\/write\.php\?info\=/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string6 = /\/hidden\-tear\-remake\.git/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string7 = /\\hidden_tear\.Form1\.resources/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string8 = /\\hidden\-tear\.csproj/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string9 = /\\hidden\-tear\.exe/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string10 = /\\hidden\-tear\.pdb/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string11 = /\\hidden\-tear\.sln/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string12 = /\\hidden\-tear\.vshost\.exe/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string13 = /\\HiddenTear\.zip/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string14 = /\\hidden\-tear\-remake\\/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string15 = /\>hidden_tear_decrypter\</ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string16 = /\>hidden\-tear\.exe\</ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string17 = /\>hidden\-tear\</ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string18 = /07dd043bc4e5ef2651ac9a1b4e5b849ce2e3dd6e3ca593a48625b568cfff924b/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string19 = /099923b629ff4309a579a66eaa857de4e5d5caa093b6226ee7c491742d9168e9/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string20 = /0xbdg\/hidden\-tear\-remake/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string21 = /19804c0341ec2408b025626ac9259438f9c403104f155eedfa9b2395d85490b3/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string22 = /2949af17b0dd766d99667bcc09646f484583cd7dcc0216fd626b517b47a91a73/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string23 = /3ce3579ba41d1ccab336da1f8768a257142c3f6eee0e8daac2605065e3a43234/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string24 = /4182eca7aebb0a2cddd4d7c069fec1295f3fcf3a48d1c2e7f690a7be6e8324e2/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string25 = /5664867318d287a388546bbb20c8d7fb7d24680a97209f4f29d25b9cb9da24ec/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string26 = /66012c3a70e772908a9e8571665562fad55a04447452b751719a80d20ebf83e7/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string27 = /660309440ef382c2966a9186161e0777d4e4fbd7b0acce8ef040e43609513282/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string28 = /79f30574ad34a49673425cb37cd038106cc9fb49615cd6a2d05986e0c7c010e2/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string29 = /7a1d50f5e8827f2b2f920811f966be5358f0a24fa52301852b32ba94146a7be6/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string30 = /82C19CBA\-E318\-4BB3\-A408\-5005EA083EC5/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string31 = /8e8f868c283b165b0ccf0da8c85458d10d785bc872007be2ee33cb756a741ceb/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string32 = /a4045cfd2b84fce0d46096b6dc9f82f8745907b5828a96b522da42cbd5f5563f/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string33 = /All\syour\simportant\sfiles\s\(documents\,\sphotos\,\svideos\,\sdatabases\,\sand\sother\sfiles\)\shave\sbeen\sencrypted\susing\sa\sstrong\sencryption\salgorithm\.\sYou\sare\sunable\sto\saccess\sthese\sfiles\sas\sthey\shave\sbeen\stransformed\sinto\sunreadable\scontent/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string34 = /b12ada1dcac400d11a462a62ec3957adbdb82a4bfb04cef08533281bdbf286a5/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string35 = /B138FFBA\-1076\-4B58\-8A98\-67B34E8A7C5C/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string36 = /c5b452ef4e7c5a5cd045419c94244148563d168a7d682baa622d113466e4a3ae/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string37 = /cd4f7b330f78c41ce8f119e1bd4c14a2da54ed3f2b1482c18247acea6411d2a4/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string38 = /Cryptolocker\-1\.0\.0\.rar/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string39 = /d7af38341aa0abbe61415eed66c9df434b901425b5c2acfe01b9619530c826a2/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string40 = /e4cfb74b6002861358363025a31d0dd682a1cb67149d6608825f63fe46d01c38/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string41 = /fb20b0f19aab92962085d0d2fbf21ccc142620e12b6cccc20f28387b6c379d65/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string42 = /Files\shas\sbeen\sencrypted\swith\shidden\stear/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string43 = /goliate\/hidden\-tear/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string44 = /hidden_tear_decrypter\.Properties\.Resources/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string45 = /hidden\-tear\-1\-master\.zip/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string46 = /hidden\-tear\-decrypter\.csproj/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string47 = /hidden\-tear\-decrypter\.exe/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string48 = /hidden\-tear\-decrypter\.pdb/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string49 = /hidden\-tear\-master\.zip/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string50 = /hidden\-tear\-remake\.zip/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string51 = /http\:\/\/utkusen\.com\/hidden\-tear\// nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string52 = /namespace\shidden_tear/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string53 = /namespace\shidden_tear\.Tools\,/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string54 = /New\sVictim\s\[\{Environment\.UserName\}/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string55 = /Send\sme\ssome\sbitcoins\sor\skebab/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string56 = /using\shidden_tear\.Tools/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string57 = /Your\sFiles\sHave\sBeen\sEncrypted\!.{0,1000}What\sHappened\sto\sMy\sFiles\?/ nocase ascii wide
        // Description: open source ransomware - many variant in the wild
        // Reference: https://github.com/goliate/hidden-tear
        $string58 = /Your\sfiles\shave\sbeen\sinfected\sand\sstolen/ nocase ascii wide

    condition:
        any of them
}
