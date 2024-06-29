rule fetch_some_proxies
{
    meta:
        description = "Detection patterns for the tool 'fetch-some-proxies' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fetch-some-proxies"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple Python script for fetching "some" (usable) proxies
        // Reference: https://github.com/stamparm/fetch-some-proxies
        $string1 = /\"https\:\/\/api\.ipify\.org\/\?format\=text\"\,\s\"https\:\/\/myexternalip\.com\/raw\"\,\s\"https\:\/\/wtfismyip\.com\/text\"\,\s\"https\:\/\/icanhazip\.com\/\"\,\s\"https\:\/\/ip4\.seeip\.org\"/ nocase ascii wide
        // Description: Simple Python script for fetching "some" (usable) proxies
        // Reference: https://github.com/stamparm/fetch-some-proxies
        $string2 = /\/fetch\-some\-proxies\.git/ nocase ascii wide
        // Description: Simple Python script for fetching "some" (usable) proxies
        // Reference: https://github.com/stamparm/fetch-some-proxies
        $string3 = /\|f\|\|e\|\|t\|\|c\|\|h\|\|\-\|\|s\|\|o\|\|m\|\|e\|\|\-\|\|p\|\|r\|\|o\|\|x\|\|i\|\|e\|\|s\|/ nocase ascii wide
        // Description: Simple Python script for fetching "some" (usable) proxies
        // Reference: https://github.com/stamparm/fetch-some-proxies
        $string4 = /daff98d2dd945ec0f5d8ef476de48e57074416a50389639d01aa54444d2cfb44/ nocase ascii wide
        // Description: Simple Python script for fetching "some" (usable) proxies
        // Reference: https://github.com/stamparm/fetch-some-proxies
        $string5 = /https\:\/\/raw\.githubusercontent\.com\/stamparm\/aux\/master\/fetch\-some\-list\.txt/ nocase ascii wide
        // Description: Simple Python script for fetching "some" (usable) proxies
        // Reference: https://github.com/stamparm/fetch-some-proxies
        $string6 = /python\s\-c\s\"import\sfetch\"/ nocase ascii wide
        // Description: Simple Python script for fetching "some" (usable) proxies
        // Reference: https://github.com/stamparm/fetch-some-proxies
        $string7 = /stamparm\/fetch\-some\-proxies/ nocase ascii wide

    condition:
        any of them
}
