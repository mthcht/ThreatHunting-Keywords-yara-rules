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
        $string1 = /.{0,1000}\sinstall\siodine.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string2 = /.{0,1000}\.\/iodined.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string3 = /.{0,1000}\/iodine\-.{0,1000}\-windows\.zip.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string4 = /.{0,1000}\/iodine\.exe.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string5 = /.{0,1000}\/iodine\.git.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string6 = /.{0,1000}\/iodine\-master\/.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string7 = /.{0,1000}\/sysconfig\/iodine\-server.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string8 = /.{0,1000}\/unstable\/net\/iodine.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string9 = /.{0,1000}\\iodine\-.{0,1000}\-windows\.zip.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string10 = /.{0,1000}\\iodine\.exe.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string11 = /.{0,1000}\\iodine\-master\\.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string12 = /.{0,1000}00cce05cfc7ac3c284be62e98c8ffb25.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string13 = /.{0,1000}3318d1dd3fcab5f3e4ab3cc5b690a3f4.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string14 = /.{0,1000}3e3fcf025697ee80f044716eee053848.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string15 = /.{0,1000}58d82bca11a41a01d0ddfa7d105e6a48.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string16 = /.{0,1000}5bb0b56e047e1453a3695ec0b9478b84.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string17 = /.{0,1000}6952343cc4614857f83dbb81247871e7.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string18 = /.{0,1000}6f2a53476cbc09bbffe7e07d6e9dd19d.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string19 = /.{0,1000}795f2e9d0314898ba5a63bd1fdc5fa18.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string20 = /.{0,1000}82d331f75a99d1547e0ccc3c3efd0a7a.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string21 = /.{0,1000}890f13ab9ee7ea722baf0ceb3ee561c0.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string22 = /.{0,1000}a15bb4faba020d217016fde6e231074a.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string23 = /.{0,1000}a201bc3c2d47775b39cd90b32eb390e7.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string24 = /.{0,1000}af2d9062b7788fc47385d8c6c645dfa0.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string25 = /.{0,1000}Aw8KAw4LDgvZDgLUz2rLC2rPBMC.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string26 = /.{0,1000}b18aca1b9e2a9e72cb77960c355d288b.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string27 = /.{0,1000}bin\/iodine.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string28 = /.{0,1000}c01fb08dabbd24b151fe5dfbb0742f7a.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string29 = /.{0,1000}cdaee04229c5aefdb806af27910f34d3.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string30 = /.{0,1000}dfbc5037fe0229e15f6f15775117aef5.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string31 = /.{0,1000}f2a64b4fce0d07eafded5c2125d7d80b.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string32 = /.{0,1000}fdbf3b81cd69caf5230d76a8b039fd99.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string33 = /.{0,1000}https:\/\/code\.kryo\.se\/iodine\/iodine\-.{0,1000}/ nocase ascii wide
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://github.com/yarrick/iodine
        $string34 = /.{0,1000}iodine\s\-.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string35 = /.{0,1000}iodine\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string36 = /.{0,1000}iodine\sIP\sover\sDNS\stunneling\sclient.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string37 = /.{0,1000}iodine\sIP\sover\sDNS\stunneling\sserver.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string38 = /.{0,1000}iodine\s\-v.{0,1000}/ nocase ascii wide
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://github.com/yarrick/iodine
        $string39 = /.{0,1000}iodined\s\-.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string40 = /.{0,1000}iodined\s\-c.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string41 = /.{0,1000}iodined\s\-f\s.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string42 = /.{0,1000}iodined\s\-v.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string43 = /.{0,1000}iodine\-latest\/.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string44 = /.{0,1000}iodine\-latest\-android\.zip.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string45 = /.{0,1000}iodine\-latest\-win32.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string46 = /.{0,1000}iodine\-latest\-windows.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string47 = /.{0,1000}iodine\-server\.service.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string48 = /.{0,1000}iodinetestingtesting.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string49 = /.{0,1000}ionide\s.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string50 = /.{0,1000}ionided\s.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string51 = /.{0,1000}nfxwi0lomv0gk21unfxgo3dfon0gs1th.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string52 = /.{0,1000}silly\.host\.of\.iodine\.code\.kryo\.se.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string53 = /.{0,1000}sudo\siodine\s.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string54 = /.{0,1000}test\-iodine\.log.{0,1000}/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string55 = /.{0,1000}yarrick\/iodine.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
