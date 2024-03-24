rule ConfuserEx
{
    meta:
        description = "Detection patterns for the tool 'ConfuserEx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ConfuserEx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string1 = /\sConfuserEx\.exe/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string2 = /\/AntiTamper\.exe/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string3 = /\/ConfuserEx\.exe/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string4 = /\/ConfuserEx\.git/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string5 = /\/ConfuserEx_bin\.zip/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string6 = /\\AntiTamper\.exe/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string7 = /\\ConfuserEx\.exe/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string8 = /\\ConfuserEx\\/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string9 = /\\ConfuserEx_bin\.zip/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string10 = /02948DD6\-47BD\-4C82\-9B4B\-78931DB23B8A/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string11 = /034B1C28\-96B9\-486A\-B238\-9C651EAA32CA/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string12 = /055BC73F\-FCAE\-4361\-B035\-2E156A101EA9/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string13 = /0C8F49D8\-BD68\-420A\-907D\-031B83737C50/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string14 = /13431429\-2DB6\-480F\-B73F\-CA019FE759E3/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string15 = /1B52A3D9\-014C\-4CBF\-BB98\-09080D9A8D16/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string16 = /211A4598\-B46E\-4CD3\-BA5A\-1EC259D4DB5A/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string17 = /2B914EE7\-F206\-4A83\-B435\-460D054315BB/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string18 = /2C059FE7\-C868\-4C6D\-AFA0\-D62BA3C1B2E1/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string19 = /2f67f590cabb9c79257d27b578d8bf9d1a278afa96b205ad2b4704e7b9a87ca7/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string20 = /30B8883F\-A0A2\-4256\-ADCF\-A790525D3696/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string21 = /32223BE8\-3E78\-489C\-92ED\-7900B26DFF43/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string22 = /32CE1CB1\-B7D9\-416F\-8EFE\-6A0055867537/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string23 = /3504F678\-95FA\-4DB2\-8437\-31A927CABC16/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string24 = /382B6332\-4A57\-458D\-96EB\-B312688A7604/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string25 = /3ADB8BB1\-AE14\-49DA\-A7E1\-1C0D9BEB76E9/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string26 = /3B85D7A9\-6BD0\-4CD8\-9009\-36554EF24D32/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string27 = /3EAB01B5\-9B49\-48D8\-BFA1\-5493B26CCB71/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string28 = /3F5558BD\-7B94\-4CB0\-A46C\-A7252B5BCA17/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string29 = /40C6A1BB\-69AA\-4869\-81EE\-41917D0B009A/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string30 = /4EF73752\-78B0\-4E0D\-A33B\-B6637B6C2177/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string31 = /4FB03AD0\-96FF\-4730\-801A\-4F997795D920/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string32 = /5D10ED0A\-6C52\-49FE\-90F5\-CFAAECA8FABE/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string33 = /5E9715AB\-CAF7\-4FFF\-8E14\-A8727891DA93/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string34 = /630BF262\-768C\-4085\-89B1\-9FEF7375F442/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string35 = /6A2BA6F7\-3399\-4890\-9453\-2D5BE8EEBBA9/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string36 = /6C8ECB51\-EECE\-49C3\-89EC\-CB0AAECCFF7E/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string37 = /73226E13\-1701\-424E\-A4F2\-3E4D575A1DD0/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string38 = /73F11EE8\-F565\-479E\-8366\-BD74EE467CE8/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string39 = /75E5F9A0\-8D69\-4426\-9F16\-4A65E941974D/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string40 = /7C6D1CCD\-D4DF\-426A\-B5D6\-A6B5F13D0091/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string41 = /8489A9CE\-AB1A\-4D8D\-8824\-D9E18B9945FE/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string42 = /862DA0DA\-52E1\-47CD\-B9C2\-46B106031B28/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string43 = /87BEF4D7\-813E\-48BA\-96FE\-E3A24BF2DC34/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string44 = /91B12706\-DC6A\-45DE\-97F1\-FAF0901FF6AF/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string45 = /9B823D93\-BF1B\-407B\-A4CD\-231347F656AD/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string46 = /9EB8DC3B\-60DC\-451E\-8C18\-3D7E38D463FD/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string47 = /A1F54816\-3FBA\-4A71\-9D26\-D31C6BE9CF01/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string48 = /A45C184F\-F98F\-4258\-A928\-BFF437034791/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string49 = /A5B912EC\-D588\-401C\-A84F\-D01F98142B9E/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string50 = /AB2E1440\-7EC2\-45A2\-8CF3\-2975DE8A57AD/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string51 = /B1CB9A30\-FEA6\-4467\-BEC5\-4803CCE9BF78/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string52 = /B5205EBA\-EC32\-4C53\-86A0\-FAEEE7393EC0/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string53 = /B7FF0EE8\-6C68\-46C6\-AADB\-58C0E3309FB2/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string54 = /BA9D2748\-1342\-41A3\-87F2\-343E82D99813/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string55 = /BEB67A6E\-4C54\-4DE5\-8C6B\-2C12F44A7B92/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string56 = /C10599E3\-5A79\-484F\-940B\-E4B61F256466/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string57 = /CD257C0A\-9071\-42B4\-A2FF\-180622DBCA96/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string58 = /CE61ADEE\-C032\-43EC\-ACD8\-E4A742F894A3/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string59 = /ConfuserEx\s\(CLI\)/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string60 = /ConfuserEx\sCommand\-line/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string61 = /ConfuserEx\sCore/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string62 = /ConfuserEx\sDynamic\sCipher\sLibrary/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string63 = /ConfuserEx\sProtections/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string64 = /ConfuserEx\sRenamer/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string65 = /ConfuserEx\sRuntime/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string66 = /ConfuserEx\.CLI\:\s/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string67 = /D1CCDA5D\-E460\-4ACC\-B51A\-730DE8F0ECF3/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string68 = /D5C4F5A2\-5713\-4A0A\-A833\-F9466AE5A339/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string69 = /D8BDABF6\-6A96\-4B48\-8C1C\-B6E78CBBF50E/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string70 = /DA7DF89C\-447D\-4C2D\-9C75\-933037BF245E/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string71 = /DAE3997B\-D51B\-4D9F\-9F11\-2EBC6FDDF57C/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string72 = /DB234158\-233E\-4EC4\-A2CE\-EF02699563A2/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string73 = /DEED6795\-9EC9\-4B2C\-95E0\-9E465DA61755/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string74 = /E17B7339\-C788\-4DBE\-B382\-3AEDB024073D/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string75 = /E7F99164\-F00F\-4B2A\-86A9\-8EB5F659F34C/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string76 = /E832E9B8\-2158\-4FC0\-89A1\-56C6ECC10F6B/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string77 = /E9D90B2A\-F563\-4A5E\-9EFB\-B1D6B1E7F8CB/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string78 = /EC62CE1D\-ADD7\-419A\-84A9\-D6A04E866197/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string79 = /F233D36D\-B64A\-4F14\-A9F9\-B8557C2D4F5D/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string80 = /F2378C48\-D441\-49E7\-B094\-1E8642A7E7C0/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string81 = /F602DAFE\-E8A2\-4CB2\-AF0E\-656CD357D821/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string82 = /F7581FB4\-FAF5\-4CD0\-888A\-B588F5BC69CD/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string83 = /FD93D181\-2EC5\-4863\-8A8F\-5F8C84C06B35/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string84 = /FE068381\-F170\-4C37\-82C4\-11A81FE60F1A/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string85 = /karing\.martin\+confusercoc\@gmail\.com/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string86 = /MessageDeobfuscation\.exe/ nocase ascii wide
        // Description: ConfuserEx is a widely used open source obfuscator often found in malware
        // Reference: https://github.com/yck1509/ConfuserEx
        $string87 = /yck1509\/ConfuserEx/ nocase ascii wide

    condition:
        any of them
}
