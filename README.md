# log-dos-finder

This tool can help to find sensible parameters for configuring `mod_evasive`,
`fail2ban`, or other DoS or DDoS detectors for your particular website, based on
existing server logs. Your goal would be to scan your current set of log
files, and find parameters that don't result in real visitors or benign
crawlers being banned, while catching the obvious bad bots. Optimal parameters
may depend on the size and design of your site.

This script analyses server log files, and will report cases where:
- the same IP accessed the same URL more than a certain number of times
  within a certain timespan.
  This is similar to `DOSPageCount` and `DOSPageInterval` in `mod_evasive`.
- the same IP did more than a certain number of requests on any URLs within
  a certain timespan.
  This is similar to `DOSSiteCount` and `DOSSiteInterval` in `mod_evasive`.

Mind that *"timespan"* does not necessarily mean a fixed interval (see the help
text and the below remark).

Supported log formats are hard-coded and currently only the ones I ever had to
deal with are supported. Pull requests for either more common formats, or a
way to specify any format as a parameter, are welcome.

## REMARKS

A common misconception is that `mod_evasive` counts requests within fixed-length
time windows. Its documentation even makes it seem as such. **WRONG:** look at the
source code and you'll see it uses a much simpler approach. A single timer is
kept per IP or IP+URL. These timers start counting back from zero EVERY time a
new request comes in, regardless of whether the new request falls within the
interval (hit count is incremented) or not. The hit count is only reset when 2
consecutive requests are further apart than the specified interval.

For instance if you set an interval of 2 seconds and a count of 10, then
indeed the detector will trip if a visitor does 10 requests within 2 seconds.
However, it will also trip if the visitor does 10 requests each with 1.9s in
between, spanning a total time of more than 17 seconds, so be very careful
when configuring these parameters.

Note that just like `mod_evasive`, we don't care about response codes. If a bot
is dumb enough to keep on doing HTTP requests despite getting a 301 redirect
each time and then doing the HTTPS request, it will hit the threshold twice as
fast, and deservedly so. Stupid bots.

Also note that even in default mode, this will not behave exactly like
'classic' `mod_evasive` (source code from 2017/02), which is inconsistent in
initialising request counts depending on whether a key is newly added to the
tree or reset when count is reset. I didn't bother replicating this behaviour
because it is bad behaviour.<br>
Moreover, since this script has a 1-second granularity for logs, sub-second
accuracy is lost and this can also cause differences between actually running
`mod_evasive` and analysing logs with this script. Of course `mod_evasive` also
has 1-second granularity, but the timing of when it is activated can make a
difference.

And last but not least, if an IP does not use a Keep-Alive connection, but
spawns new connections all the time, then those requests will usually be
handled by different Apache workers. Those have each their own `mod_evasive`
instance with their own database, and they will not trigger the thresholds as
soon as you may expect. This script however does not know what log lines come
from different connections, hence again it may report cases that `mod_evasive`
wouldn't. This is a weakness of `mod_evasive` that can be mitigated by using
something like fail2ban instead, that acts on log files.

