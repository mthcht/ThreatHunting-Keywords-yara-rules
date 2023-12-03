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
        $string1 = /.{0,1000}\/0d1n\.c.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string2 = /.{0,1000}\/0d1n_view.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string3 = /.{0,1000}\/bin\/0d1n.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string4 = /.{0,1000}\/crlfinjection\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string5 = /.{0,1000}\/dir_brute\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string6 = /.{0,1000}\/js_inject\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string7 = /.{0,1000}\/ldap_injection\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string8 = /.{0,1000}\/passive_sqli\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string9 = /.{0,1000}\/password_brute\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string10 = /.{0,1000}\/path_traversal\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string11 = /.{0,1000}\/path_traversal_win32\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string12 = /.{0,1000}\/sqli\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string13 = /.{0,1000}\/xml_attack\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string14 = /.{0,1000}\/xml_attacks\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string15 = /.{0,1000}\/xpath_injection\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string16 = /.{0,1000}\/xss_robertux\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string17 = /.{0,1000}\/xxe_fuzz\.txt.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string18 = /.{0,1000}0d1n\s.{0,1000}\s\-\-post\s.{0,1000}\s\-\-payloads\s.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string19 = /.{0,1000}0d1n\s\-\-host.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string20 = /.{0,1000}0d1n.{0,1000}kill_listener\.sh.{0,1000}/ nocase ascii wide
        // Description: Tool for automating customized attacks against web applications. Fully made in C language with pthreads it has fast performance.
        // Reference: https://github.com/CoolerVoid/0d1n
        $string21 = /.{0,1000}CoolerVoid\/0d1n.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
