import cpp
from MacroInvocation mi
where mi.getMacroName().regexpMatch("ntoh(s|(ll?))")
select mi.getExpr(), "expression of ntoh*"
