rule WDExtract
{
    meta:
        description = "Detection patterns for the tool 'WDExtract' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WDExtract"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string1 = /\/wdextract\.cpp/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string2 = /\/wdextract\.cpp/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string3 = /\/WDExtract\.git/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string4 = /\/wdextract32\.exe/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string5 = /\/wdextract64\.exe/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string6 = /\\wdextract\.cpp/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string7 = /\\wdextract\.sln/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string8 = /\\wdextract\.vcxproj/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string9 = /\\wdextract32\.exe/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string10 = /\\wdextract64\.exe/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string11 = /04b99fb5cc1d91b1752fbcb2446db71083ab87af59dd9e0d940cc2ed5a65ef49/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string12 = /086e302c10b4dc16180cdb87a84844a9b49b633ea6e965ad0db2319adb2af86e/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string13 = /08AEC00F\-42ED\-4E62\-AE8D\-0BFCE30A3F57/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string14 = /124e6ada27ffbe0ff97f51eb9d7caaf86b531bcff90ed5a075ff89b45b00cba5/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string15 = /1f047faec08d9a35c304fb4a7cf13853589359a8f7cbfdd48c5d5807712dcf05/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string16 = /1f047faec08d9a35c304fb4a7cf13853589359a8f7cbfdd48c5d5807712dcf05/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string17 = /21582b3a68e8753322a1b1c7e550ae7fd305de4935de68fbde9f87570f484d00/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string18 = /21582b3a68e8753322a1b1c7e550ae7fd305de4935de68fbde9f87570f484d00/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string19 = /4d262988fe9d252191947ab780535d496ed24fa27668cf76c6cb9b6474a391c4/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string20 = /4ddc82b4af931ab55f44d977bde81bfbc4151b5dcdccc03142831a301b5ec3c8/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string21 = /6b95cd81ca4f309ac9f243ae73d2e8099634aaffead5b7b214bfcd14b6d604f6/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string22 = /6e537702f0e29ddd6c134a1020396f42c30cd69da213d3fddfa645fc77c2449d/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string23 = /77b78b6e16972c318fcbba39976858787cc31038f82952d2a94f844f5847a61e/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string24 = /8304a65e6096bcf63f30592b8049d47883c3c755600796c60a36c4c492f7af37/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string25 = /928097a924168caad66fead2633e4d44e4f585e0d33d05deb50b9c2d34cda246/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string26 = /9c0087f31cd45fe4bfa0ca79b51df2c69d67c44f2fbb2223d7cf9ab8d971c360/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string27 = /a6730ebb3e91961283f7a1cd95ace2a6d0d55e50531a64e57b03e61a8cf2d0e7/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string28 = /beb285e40caf95bcc1552fc293194fa29275e3cdb9c62ef752b62257f6480aaf/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string29 = /Bin\\bin32\\zlibwapi\.dll/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string30 = /Bin\\bin64\\zlibwapi\.dll/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string31 = /d091e408c0c5068b86bb69d17e91c5a7d6da46c0bd4101aa14f136246aed7f51/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string32 = /d0ebb728926cce530040e046a8ea2f47e01158581cb0b5cccddc91007b421f6c/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string33 = /d38210acb6d0568559041036abd033953c4080170e1ea9cf5d4d8499b54141b7/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string34 = /dc3d98a8e8c0b0944291f9b462f552f174261982c4507f2de1ee9503353d10e9/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string35 = /ExtractDataXML_BruteForce/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string36 = /hfiref0x\/WDExtract/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string37 = /Source\\wdextract\\/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string38 = /Source\\wdextract\\zlib\\dll_x64\\zlibwapi\.dll/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string39 = /Source\\wdextract\\zlib\\dll_x86\\zlibwapi\.dll/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string40 = /Source\\wdextract\\zlib\\lib\\zlibwapi32\.lib/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string41 = /Source\\wdextract\\zlib\\lib\\zlibwapi64\.lib/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string42 = /wdextract\s.{0,1000}\:\\.{0,1000}\\.{0,1000}\.vdm/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string43 = /wdextract\s.{0,1000}\\mrt\.exe/ nocase ascii wide
        // Description: Extract Windows Defender database from vdm files and unpack it
        // Reference: https://github.com/hfiref0x/WDExtract/
        $string44 = /WDExtract\-master/ nocase ascii wide

    condition:
        any of them
}
