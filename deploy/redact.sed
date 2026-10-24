# redact.sed -- masks credential-shaped text in deployment output.
#
# Applied with `sed -E -f` by the CD workflow to everything the instance
# prints, and embedded verbatim in deploy.sh for the log excerpts it shows.
# deploy/tests/run-tests.sh checks that the two copies match. Keep it portable
# (GNU and BSD sed, no I flag): case-insensitive words are spelled out.
#
# Credentials in URLs: scheme://user:password@host
s#(://[^:/@[:space:]]+:)[^@[:space:]]+@#\1****@#g
# PEM private keys: a key on one line, then every line from BEGIN to END (or to
# the end of the output, if it was cut off).
s#-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*-----END [A-Z0-9 ]*PRIVATE KEY-----#[redacted private key]#g
/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,/-----END [A-Z0-9 ]*PRIVATE KEY-----/s#.*#[redacted private key]#
# Authorization headers, and bearer tokens anywhere.
s#([Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]["']?[[:space:]]*[:=][[:space:]]*)[^",']+#\1****#g
s#([Bb][Ee][Aa][Rr][Ee][Rr][[:space:]]+)[A-Za-z0-9._~+/=-]+#\1****#g
# key=value and key: value, where the key names a credential.
s#([A-Za-z0-9_.-]*([Pp][Aa][Ss][Ss][Ww]([Oo][Rr])?[Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Kk][Ee][Yy]|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Kk][Ee][Yy]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll])[A-Za-z0-9_.-]*["']?[[:space:]]*[:=][[:space:]]*["']?)[^[:space:],"']+#\1****#g
# Well-known token formats, wherever they appear: GitHub, AWS access key IDs,
# Slack, JWTs, Google API keys, sk- style API keys, Stripe.
s#gh[pousr]_[A-Za-z0-9]{20,}#****#g
s#github_pat_[A-Za-z0-9_]{20,}#****#g
s#(AKIA|ASIA)[A-Z0-9]{16}#****#g
s#xox[abposr]-[A-Za-z0-9-]{10,}#****#g
s#eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}#****#g
s#AIza[0-9A-Za-z_-]{35}#****#g
s#sk-[A-Za-z0-9_-]{20,}#****#g
s#(sk|rk)_(live|test)_[0-9A-Za-z]{16,}#****#g
