import cpp

from Macro m
where m.getName().regexpMatch("ntoh(s|(ll?))")
select m, "a macro named ntohl, ntohll or ntohs"