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
        $string1 = /\/Quasar\.git/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string2 = /\/Quasar\.v.{0,1000}\.zip/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string3 = /\/Quasar\/releases/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string4 = /\\Quasar\.v.{0,1000}\.zip/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string5 = /\\Quasar\-master/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string6 = /CFCD0759E20F29C399C9D4210BE614E4E020BEE8/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string7 = /localhost\:4782/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string8 = /Quasar\.Client\./ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string9 = /Quasar\.exe/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string10 = /Quasar\.Server/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string11 = /Quasar\.sln/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string12 = /quasar\/Quasar/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string13 = /Quasar\-master\.zip/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string14 = /QuasarRAT/ nocase ascii wide
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string15 = /ylAo2kAlUS2kYkala\!/ nocase ascii wide

    condition:
        any of them
}
