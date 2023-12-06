rule _0d1n
{
    meta:
        description = "Detection patterns for the tool '0d1n' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "0d1n"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string1 = /\/0d1n\.c/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string2 = /\/0d1n_view/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string3 = /\/bin\/0d1n/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string4 = /\/crlfinjection\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string5 = /\/dir_brute\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string6 = /\/js_inject\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string7 = /\/ldap_injection\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string8 = /\/passive_sqli\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string9 = /\/password_brute\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string10 = /\/path_traversal\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string11 = /\/path_traversal_win32\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string12 = /\/sqli\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string13 = /\/xml_attack\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string14 = /\/xml_attacks\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string15 = /\/xpath_injection\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string16 = /\/xss_robertux\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string17 = /\/xxe_fuzz\.txt/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string18 = /0d1n\s.{0,1000}\s\-\-post\s.{0,1000}\s\-\-payloads\s/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string19 = /0d1n\s\-\-host/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string20 = /0d1n.{0,1000}kill_listener\.sh/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string21 = /CoolerVoid\/0d1n/ nocase ascii wide

    condition:
        any of them
}
