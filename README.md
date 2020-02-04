# Scraper
Adds extensibility to Burp by using a list of payloads to pattern match on HTTP responses highlighting interesting and potentially vulnerable areas. Can be used to search HTML source code for interesting keywords, developer comments, passwords, admin panel links, hidden form fields, and more.

# Running
The .jar file is available in the /releases directory, this can be loaded in through Burp Extender.
<ol>
<li>On the Scraper tab configure the payloads
<li>configure regex (explain Java regex)
<li>configure your scope
<li>select scope
<li>Test as normal, observe the Sample Extract column for matches

#Acknowledgements
Author: Jack Jarvis, NCC Group <br/>
Developed using IntelliJ IDE and the Gradle Build Tool.

For further Burp Extension development please refer to:<br />
https://portswigger.net/burp/extender/api/<br />
https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension<br />
https://portswigger.net/burp/extender