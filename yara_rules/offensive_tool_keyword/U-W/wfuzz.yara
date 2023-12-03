rule wfuzz
{
    meta:
        description = "Detection patterns for the tool 'wfuzz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wfuzz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string1 = /.{0,1000}\sadmin\-panels\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string2 = /.{0,1000}\sAll_attack\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string3 = /.{0,1000}\s\-c\s\-w\s.{0,1000}\.txt\s\-w\s.{0,1000}\.txt\s\-\-ss\s.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string4 = /.{0,1000}\s\-c\s\-w\smethods\.txt\s\-p\s127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string5 = /.{0,1000}\s\-c\s\-w\susers\.txt\s\-\-hs\s.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string6 = /.{0,1000}\s\-c\s\-z\sfile.{0,1000}users\.txt\s\-z\sfile.{0,1000}pass\.txt\s.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string7 = /.{0,1000}\s\-c\s\-z\srange.{0,1000}1\-10\s\-\-hc\=BBB\shttp.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string8 = /.{0,1000}\scommon_pass\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string9 = /.{0,1000}\sFUZZ:FUZZ\s.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string10 = /.{0,1000}\sinstall\swfuzz.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string11 = /.{0,1000}\s\-\-script\=robots\s\-z\slist.{0,1000}robots\.txt.{0,1000}http.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string12 = /.{0,1000}\s\-u\sFUZZ\s.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string13 = /.{0,1000}\s\-w\swordlist\/.{0,1000}\.txt.{0,1000}http.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string14 = /.{0,1000}\sws\-dirs\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string15 = /.{0,1000}\sws\-files\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string16 = /.{0,1000}\s\-X\sFUZZ\shttp.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string17 = /.{0,1000}\s\-z\sburplog.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string18 = /.{0,1000}\s\-z\sfile.{0,1000}wordlist\/.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string19 = /.{0,1000}\s\-z\slist.{0,1000}nonvalid\-httpwatch\s\-\-basic.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string20 = /.{0,1000}\s\-z\srange\s\-\-zD\s0\-1\s\-u\shttp.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string21 = /.{0,1000}\s\-z\srange.{0,1000}0\-10\s\-\-hl\s97\shttp.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string22 = /.{0,1000}\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string23 = /.{0,1000}\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/shadow.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string24 = /.{0,1000}\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/boot\.ini.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string25 = /.{0,1000}\/admin\-panels\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string26 = /.{0,1000}\/All_attack\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string27 = /.{0,1000}\/common_pass\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string28 = /.{0,1000}\/Injections\/SQL\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string29 = /.{0,1000}\/sql_inj\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string30 = /.{0,1000}\/ws\-dirs\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string31 = /.{0,1000}\/ws\-files\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string32 = /.{0,1000}\\admin\-panels\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string33 = /.{0,1000}\\All_attack\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string34 = /.{0,1000}\\common_pass\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string35 = /.{0,1000}\\ws\-dirs\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string36 = /.{0,1000}\\ws\-files\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string37 = /.{0,1000}buffer_overflow\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string38 = /.{0,1000}burp_log_.{0,1000}\.log.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string39 = /.{0,1000}burpitem\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string40 = /.{0,1000}burplog\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string41 = /.{0,1000}burpstate\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string42 = /.{0,1000}dirTraversal\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string43 = /.{0,1000}dirTraversal\-nix\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string44 = /.{0,1000}dirTraversal\-win\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string45 = /.{0,1000}dirwalk\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string46 = /.{0,1000}from\s\.core\simport\sFuzzer.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string47 = /.{0,1000}from\s\.wfuzz\simport\s.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string48 = /.{0,1000}fuzzfactory\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string49 = /.{0,1000}fuzzrequest\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string50 = /.{0,1000}http:\/\/127\.0\.0\.1\/FUZZ.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string51 = /.{0,1000}http:\/\/wfuzz\.org.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string52 = /.{0,1000}https:\/\/wfuzz\.readthedocs\.io.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string53 = /.{0,1000}import\swfuzz.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string54 = /.{0,1000}Injections\/Traversal\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string55 = /.{0,1000}Injections\/XSS\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string56 = /.{0,1000}shodanp\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string57 = /.{0,1000}site\-packages\/wfuzz.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string58 = /.{0,1000}subdomains\-top1million\-20000\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string59 = /.{0,1000}uname\=FUZZ\&pass\=FUZZ.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string60 = /.{0,1000}vulns\/apache\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string61 = /.{0,1000}vulns\/iis\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string62 = /.{0,1000}vulns\/jrun\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string63 = /.{0,1000}vulns\/tomcat\.txt.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string64 = /.{0,1000}vulnweb\.com\/FUZZ.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string65 = /.{0,1000}wfencode\s\-.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string66 = /.{0,1000}wfencode\s\-e\s.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string67 = /.{0,1000}wfencode\.bat.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string68 = /.{0,1000}wfencode\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string69 = /.{0,1000}wfpayload\s\-.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string70 = /.{0,1000}wfpayload\.bat.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string71 = /.{0,1000}wfpayload\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string72 = /.{0,1000}wfuzz.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string73 = /.{0,1000}wfuzz\.bat.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string74 = /.{0,1000}wfuzz\.get_payload.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string75 = /.{0,1000}wfuzz\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string76 = /.{0,1000}wfuzz\.wfuzz.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string77 = /.{0,1000}wfuzz\-cli\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string78 = /.{0,1000}wfuzzp\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string79 = /.{0,1000}www\.wfuzz\.org.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string80 = /.{0,1000}wxfuzz\.bat.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string81 = /.{0,1000}wxfuzz\.py.{0,1000}/ nocase ascii wide
        // Description: Web application fuzzer.
        // Reference: https://github.com/xmendez/wfuzz
        $string82 = /.{0,1000}xmendez\/wfuzz.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
