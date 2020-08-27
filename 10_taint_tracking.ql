import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph
 
class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        // check this against all macro 
        // invocations for ntoh
        // returns true if this is one
        exists(MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
        ) 

    }
}


class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    // convert Node to source and test if it
    // belongs to our NetworkByteSwap class
    source.asExpr() instanceof NetworkByteSwap
  }
  override predicate isSink(DataFlow::Node sink) {
    // Test if sink node is a size argument to memcpy. Arguments are numbered from 0, n-1
    exists ( FunctionCall call
        | sink.asExpr() = call.getArgument(2) and 
          call.getTarget().getName() = "memcpy" 
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
