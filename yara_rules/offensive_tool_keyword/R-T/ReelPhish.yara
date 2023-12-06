rule ReelPhish
{
    meta:
        description = "Detection patterns for the tool 'ReelPhish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReelPhish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ReelPhish consists of two components: the phishing site handling code and this script. The phishing site can be designed as desired. Sample PHP code is provided in /examplesitecode. The sample code will take a username and password from a HTTP POST request and transmit it to the phishing script.  The phishing script listens on a local port and awaits a packet of credentials. Once credentials are received. the phishing script will open a new web browser instance and navigate to the desired URL (the actual site where you will be entering a users credentials). Credentials will be submitted by the web browser
        // Reference: https://github.com/fireeye/ReelPhish
        $string1 = /ReelPhish/ nocase ascii wide

    condition:
        any of them
}
