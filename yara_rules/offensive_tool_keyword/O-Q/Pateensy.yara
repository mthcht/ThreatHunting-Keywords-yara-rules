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
        $string1 = /.{0,1000}\/paensy\.cpp.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string2 = /.{0,1000}BadUSB_AddAdmin\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string3 = /.{0,1000}BadUSB_DownloadExecute\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string4 = /.{0,1000}BadUSB_FacebookPost\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string5 = /.{0,1000}BadUSB_HideWindow\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string6 = /.{0,1000}BadUSB_LockYourComputer\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string7 = /.{0,1000}Bye_Explorer\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string8 = /.{0,1000}Pateensy\/PaensyLib\/.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string9 = /.{0,1000}powershell\-admin\-download\-execute\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string10 = /.{0,1000}screetsec\/Pateensy.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string11 = /.{0,1000}Teensypreter\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string12 = /.{0,1000}WiFi_Hacker\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string13 = /.{0,1000}Windows7\-BypassLogon\-Screen\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string14 = /.{0,1000}windows\-forkbomb\.ino.{0,1000}/ nocase ascii wide
        // Description: payload for teensy like a rubber ducky but the syntax is different. this Human interfaes device ( HID attacks ). Penetration With Teensy
        // Reference: https://github.com/screetsec/Pateensy
        $string15 = /.{0,1000}You_spin_me__round\.ino.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
