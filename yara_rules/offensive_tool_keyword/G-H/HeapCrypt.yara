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
        $string1 = /\/HeapCrypt\.git/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string2 = /83035080\-7788\-4EA3\-82EE\-6C06D2E6891F/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string3 = /HeapCrypt\-main/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string4 = /HeapEncryptDecrypt\.cpp/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string5 = /HeapEncryptDecrypt\.exe/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string6 = /HeapEncryptDecrypt\.sln/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string7 = /HeapEncryptDecrypt\.vcxproj/ nocase ascii wide
        // Description: Encypting the Heap while sleeping by hooking and modifying Sleep with our own sleep that encrypts the heap
        // Reference: https://github.com/TheD1rkMtr/HeapCrypt
        $string8 = /TheD1rkMtr\/HeapCrypt/ nocase ascii wide

    condition:
        any of them
}
