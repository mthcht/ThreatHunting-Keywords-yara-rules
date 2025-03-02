rule php_reverse_shell
{
    meta:
        description = "Detection patterns for the tool 'php-reverse-shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "php-reverse-shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string1 = /\snew\sSh\(\'127\.0\.0\.1\'\,9000\)/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string2 = /\/php_reverse_shell\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string3 = /\/php\-reverse\-shell\.git/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string4 = "/php-reverse-shell/releases/" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string5 = "/php-reverse-shell/zipball/" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string6 = "009e013613ce6435e4a83fadf560f9b19e3adbb774ae2d7daab7fef6e6bd586d" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string7 = "00e574776767b1adaccff7b62bdb544633c806d5bde00c267edbcd3459e23d89" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string8 = "12eb25ef52882b1d26acfcdd8eedc223874bcc405be27cc669fa655f2564c64e" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string9 = "3ee55b131560263d8f4d9a971e7a82e07b9b80db67fd9496ba2d2b0aeeaa2759" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string10 = "64ce94651ee719279668c5d3bcfb376da9993aba306dc8b7f1e4def4c6917312" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string11 = "6727e1988ae996df818696de98826a6dcf0e0fc3dd7e32cf9247b41fa225b856" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string12 = "8596bb9703901bd2b0174aa550288f303e26f27d72a26daff201e7ea709da002" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string13 = "94fcbb0aadcaaeae36a043eee19005e3e6ae2c991a389291fef7d4ecbe68aeb5" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string14 = "ab574153b5e7f7bef16f38ab53fcb107e2b1459426a73acf6fdd41434c94fa94" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string15 = "c949913be70a42e2ea9395d2a2e7ac427cdc0d756b6b12d1e607ba3e11937e35" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string16 = "ca3560757b7667c3b9ac2cca3b586493ef266b2b0591c1252d35f9e3a39cad08" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string17 = "d28ac4233d53079b9f57c3dd15c024feaaffd407b26568da298c87c5d563c60c" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string18 = "ivan-sincek/php-reverse-shell" nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string19 = /new\sShell\(\'127\.0\.0\.1\'\,\s9000\)/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string20 = /php_reverse_shell_mini\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string21 = /php_reverse_shell_older\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string22 = /php_reverse_shell_older_mini\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string23 = /simple_php_web_shell_get\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string24 = /simple_php_web_shell_get\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string25 = /simple_php_web_shell_get__mini_v2\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string26 = /simple_php_web_shell_get_mini\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string27 = /simple_php_web_shell_get_v2\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string28 = /simple_php_web_shell_get_v2\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string29 = /simple_php_web_shell_post\.php/ nocase ascii wide
        // Description: PHP shells that work on Linux OS - macOS and Windows OS
        // Reference: https://github.com/ivan-sincek/php-reverse-shell
        $string30 = /simple_php_web_shell_post_mini\.php/ nocase ascii wide

    condition:
        any of them
}
