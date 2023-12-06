rule Pateensy
{
    meta:
        description = "Detection patterns for the tool 'Pateensy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pateensy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string1 = /\/paensy\.cpp/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string2 = /BadUSB_AddAdmin\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string3 = /BadUSB_DownloadExecute\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string4 = /BadUSB_FacebookPost\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string5 = /BadUSB_HideWindow\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string6 = /BadUSB_LockYourComputer\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string7 = /Bye_Explorer\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string8 = /Pateensy\/PaensyLib\// nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string9 = /powershell\-admin\-download\-execute\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string10 = /screetsec\/Pateensy/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string11 = /Teensypreter\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string12 = /WiFi_Hacker\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string13 = /Windows7\-BypassLogon\-Screen\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string14 = /windows\-forkbomb\.ino/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string15 = /You_spin_me__round\.ino/ nocase ascii wide

    condition:
        any of them
}
