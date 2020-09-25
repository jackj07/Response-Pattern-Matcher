# Response Pattern Matcher
Adds extensibility to Burp by using a list of payloads to pattern match on HTTP responses highlighting interesting and potentially vulnerable areas. Can be used to search HTML source code for interesting keywords, developer comments, passwords, admin panel links, hidden form fields, and more.

# Usage
The .jar file is available in the /releases directory, this can be loaded in through Burp Extender.
<ol>
<li>When the extension is loaded in you will see a Response Pattern Matcher tab, by default pre-existing payloads exist that will be pattern matched against every response that goes through Burp. This includes tools such as the Scanner.</li>
<li>Configure these payloads accordingly, these are quite generic so for an assessment you may want to add project specific keywords and regular expressions.</li>
<li>The is regex check box indicates whether to search the responses for the provided Pattern using Java's Pattern Matcher functionality. A good example is available below.</li>
<li>The active check box indicates whether the payload will be searched for in each response. Uncheck this to disable the payload.</li>
<li>Use the "In Scope Only" checkbox to search only within responses that are in Scope defined under <i>Target > Scope</i>.</li>
<li>For best results, define your scope, configure your payloads, and <b>then</b> start testing. Burp's Scanner will kick in and push everything through the Response Pattern Matcher too so the tool searches the full sitemap.</li>
<li><b>Note</b> /* cannot be set to be regex, this will most likely crash burp as it matches on everything.</li>
</ol>

[Java regex tutorial](http://vogella.com/tutorials/JavaRegularExpressions/article.html)

# Requirements
Built using Java 12.0.2, runs on Burp v2.

# Acknowledgements
<b>Author</b>: Jack Jarvis, NCC Group <br/>
Developed using IntelliJ IDE and the Gradle Build Tool.
<br/><br/>
CoreyD97 Burp Extender Utilities:<br/>
https://github.com/CoreyD97/BurpExtenderUtilities
<br/><br/>
For further Burp Extension development please refer to:<br />
https://portswigger.net/burp/extender/api/<br />
https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension<br />
https://portswigger.net/burp/extender