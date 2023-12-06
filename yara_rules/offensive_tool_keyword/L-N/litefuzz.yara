rule litefuzz
{
    meta:
        description = "Detection patterns for the tool 'litefuzz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "litefuzz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string1 = /\.\/litefuzz\.py/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string2 = /\/sec\-tools\/litefuzz/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string3 = /AcroRd32\.exe\sFUZZ/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string4 = /antiword\sFUZZ/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string5 = /litefuzz\s\-lk\s\-c/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string6 = /litefuzz\s\-s\s\-a\s/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string7 = /litefuzz.{0,1000}\s\-l\s\-c/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string8 = /litefuzz\.py\s/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string9 = /litefuzz\\fuzz\.py/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string10 = /\-\-mutator\sN/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string11 = /mutator\.py\s/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string12 = /notepad\sFUZZ/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string13 = /puttygen\.exe\sFUZZ/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string14 = /test_litefuzz\.py/ nocase ascii wide

    condition:
        any of them
}
