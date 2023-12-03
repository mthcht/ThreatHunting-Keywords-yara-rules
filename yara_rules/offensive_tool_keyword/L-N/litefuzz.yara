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
        $string1 = /.{0,1000}\.\/litefuzz\.py.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string2 = /.{0,1000}\/sec\-tools\/litefuzz.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string3 = /.{0,1000}AcroRd32\.exe\sFUZZ.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string4 = /.{0,1000}antiword\sFUZZ.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string5 = /.{0,1000}litefuzz\s\-lk\s\-c.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string6 = /.{0,1000}litefuzz\s\-s\s\-a\s.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string7 = /.{0,1000}litefuzz.{0,1000}\s\-l\s\-c.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string8 = /.{0,1000}litefuzz\.py\s.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string9 = /.{0,1000}litefuzz\\fuzz\.py.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string10 = /.{0,1000}\-\-mutator\sN.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string11 = /.{0,1000}mutator\.py\s.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string12 = /.{0,1000}notepad\sFUZZ.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string13 = /.{0,1000}puttygen\.exe\sFUZZ.{0,1000}/ nocase ascii wide
        // Description: A multi-platform fuzzer for poking at userland binaries and servers
        // Reference: https://github.com/sec-tools/litefuzz
        $string14 = /.{0,1000}test_litefuzz\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
