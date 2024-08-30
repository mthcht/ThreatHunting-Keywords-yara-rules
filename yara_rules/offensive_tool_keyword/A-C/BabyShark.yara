rule BabyShark
{
    meta:
        description = "Detection patterns for the tool 'BabyShark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BabyShark"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string1 = /\/BabyShark\.git/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string2 = /\/home\/daddyShark\/BabySh4rk\// nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string3 = /\/momyshark\.html/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string4 = /\/momyshark\.html/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string5 = /\/momyshark\?key\=/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string6 = /\/sharklog\.log/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string7 = /\\BabyShark\-master\.zip/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string8 = /\\sharklog\.log/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string9 = /283516d3927c180b3f4b8d90cefaaf34ff66a5250f218fa327e194f71748e015/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string10 = /7716e96debd76da60e286c09150ced547e6e7ed8cba8231d0612d92941833591/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string11 = /78be236127f4f8c65a8a9818b43e32e33a9107325e14b80f53337cd34b8c53e8/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string12 = /BabySh4rk\s\-\sMomySh4rk/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string13 = /danilovazb\/BabyShark/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string14 = /database\/c2\.db/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string15 = /password\s\=\s\'b4bysh4rk\'/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string16 = /sqlite3\sdatabase\/c2\.db/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string17 = /translate\.google\.com\/translate\?\&anno\=2\&u\=\$c2server/ nocase ascii wide
        // Description: This is a basic C2 generic server written in Python and Flask.
        // Reference: https://github.com/UnkL4b/BabyShark
        $string18 = /UnkL4b\/BabyShark/ nocase ascii wide

    condition:
        any of them
}
