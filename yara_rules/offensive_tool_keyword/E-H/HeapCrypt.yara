rule HeapCrypt
{
    meta:
        description = "Detection patterns for the tool 'HeapCrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HeapCrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string1 = /.{0,1000}\/HeapCrypt\.git.{0,1000}/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string2 = /.{0,1000}83035080\-7788\-4EA3\-82EE\-6C06D2E6891F.{0,1000}/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string3 = /.{0,1000}HeapCrypt\-main.{0,1000}/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string4 = /.{0,1000}HeapEncryptDecrypt\.cpp.{0,1000}/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string5 = /.{0,1000}HeapEncryptDecrypt\.exe.{0,1000}/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string6 = /.{0,1000}HeapEncryptDecrypt\.sln.{0,1000}/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string7 = /.{0,1000}HeapEncryptDecrypt\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string8 = /.{0,1000}TheD1rkMtr\/HeapCrypt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
