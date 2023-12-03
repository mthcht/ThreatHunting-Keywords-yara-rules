rule QuasarRAT
{
    meta:
        description = "Detection patterns for the tool 'QuasarRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "QuasarRAT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string1 = /.{0,1000}\/Quasar\.git.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string2 = /.{0,1000}\/Quasar\.v.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string3 = /.{0,1000}\/Quasar\/releases.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string4 = /.{0,1000}\\Quasar\.v.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string5 = /.{0,1000}\\Quasar\-master.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string6 = /.{0,1000}CFCD0759E20F29C399C9D4210BE614E4E020BEE8.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string7 = /.{0,1000}localhost:4782.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string8 = /.{0,1000}Quasar\.Client\..{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string9 = /.{0,1000}Quasar\.exe.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string10 = /.{0,1000}Quasar\.Server.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string11 = /.{0,1000}Quasar\.sln.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string12 = /.{0,1000}quasar\/Quasar.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string13 = /.{0,1000}Quasar\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string14 = /.{0,1000}QuasarRAT.{0,1000}/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string15 = /.{0,1000}ylAo2kAlUS2kYkala\!.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
