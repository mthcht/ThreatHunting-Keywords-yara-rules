rule cheetah
{
    meta:
        description = "Detection patterns for the tool 'cheetah' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cheetah"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string1 = /\s\-p\spwd1\.list\spwd2\.list\s/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string2 = /\/big_shell_pwd\.7z/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string3 = /\/cheetah\.git/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string4 = /\/cheetah\.py/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string5 = /\\big_shell_pwd\.7z/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string6 = /\\cheetah\.py/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string7 = /\\cheetah\-master\.zip/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string8 = /5a1f9b0e\-9f7c\-4673\-bf16\-4740707f41b7/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string9 = /a\svery\sfast\sbrute\sforce\swebshell\spassword\stool\./ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string10 = /cheetah\.py\s\-/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string11 = /git\sclone\s.{0,1000}\s\/tmp\/cheetah/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string12 = /http\:\/\/localhost\/shell\.jsp\?pwd\=System\.out\.println\(/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string13 = /run\s\-\-rm\s\-it\sxshuden\/cheetah/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string14 = /shmilylty\/cheetah/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string15 = /sunnyelf\/cheetah\/archive\/master\.zip/ nocase ascii wide
        // Description: a very fast brute force webshell password tool
        // Reference: https://github.com/shmilylty/cheetah
        $string16 = /sunnyelf\[\@hackfun\.org\]/ nocase ascii wide

    condition:
        any of them
}
