rule iodine
{
    meta:
        description = "Detection patterns for the tool 'iodine' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iodine"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string1 = /\sinstall\siodine/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string2 = /\.\/iodined/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string3 = /\/iodine\-.{0,1000}\-windows\.zip/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string4 = /\/iodine\.exe/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string5 = /\/iodine\.git/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string6 = /\/iodine\-master\// nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string7 = /\/sysconfig\/iodine\-server/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string8 = /\/unstable\/net\/iodine/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string9 = /\\iodine\-.{0,1000}\-windows\.zip/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string10 = /\\iodine\.exe/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string11 = /\\iodine\-master\\/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string12 = /00cce05cfc7ac3c284be62e98c8ffb25/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string13 = /3318d1dd3fcab5f3e4ab3cc5b690a3f4/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string14 = /3e3fcf025697ee80f044716eee053848/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string15 = /58d82bca11a41a01d0ddfa7d105e6a48/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string16 = /5bb0b56e047e1453a3695ec0b9478b84/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string17 = /6952343cc4614857f83dbb81247871e7/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string18 = /6f2a53476cbc09bbffe7e07d6e9dd19d/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string19 = /795f2e9d0314898ba5a63bd1fdc5fa18/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string20 = /82d331f75a99d1547e0ccc3c3efd0a7a/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string21 = /890f13ab9ee7ea722baf0ceb3ee561c0/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string22 = /a15bb4faba020d217016fde6e231074a/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string23 = /a201bc3c2d47775b39cd90b32eb390e7/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string24 = /af2d9062b7788fc47385d8c6c645dfa0/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string25 = /Aw8KAw4LDgvZDgLUz2rLC2rPBMC/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string26 = /b18aca1b9e2a9e72cb77960c355d288b/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string27 = /bin\/iodine/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string28 = /c01fb08dabbd24b151fe5dfbb0742f7a/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string29 = /cdaee04229c5aefdb806af27910f34d3/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string30 = /dfbc5037fe0229e15f6f15775117aef5/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string31 = /f2a64b4fce0d07eafded5c2125d7d80b/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string32 = /fdbf3b81cd69caf5230d76a8b039fd99/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string33 = /https:\/\/code\.kryo\.se\/iodine\/iodine\-/ nocase ascii wide
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://github.com/yarrick/iodine
        $string34 = /iodine\s\-/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string35 = /iodine\s\-f\s/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string36 = /iodine\sIP\sover\sDNS\stunneling\sclient/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string37 = /iodine\sIP\sover\sDNS\stunneling\sserver/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string38 = /iodine\s\-v/ nocase ascii wide
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://github.com/yarrick/iodine
        $string39 = /iodined\s\-/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string40 = /iodined\s\-c/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string41 = /iodined\s\-f\s/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string42 = /iodined\s\-v/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string43 = /iodine\-latest\// nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string44 = /iodine\-latest\-android\.zip/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string45 = /iodine\-latest\-win32/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string46 = /iodine\-latest\-windows/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string47 = /iodine\-server\.service/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string48 = /iodinetestingtesting/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string49 = /ionide\s/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string50 = /ionided\s/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string51 = /nfxwi0lomv0gk21unfxgo3dfon0gs1th/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string52 = /silly\.host\.of\.iodine\.code\.kryo\.se/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string53 = /sudo\siodine\s/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string54 = /test\-iodine\.log/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string55 = /yarrick\/iodine/ nocase ascii wide

    condition:
        any of them
}
