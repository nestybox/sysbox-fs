package main

type handlerTemplate interface {
	init()
	exec()
}

var cpuInfoTemplate = `processor       : {{ index . "processor" }}
vendor_id       : {{ index . "vendor_id" }}
cpu family      : {{ index . "cpu family" }}
model           : {{ index . "model" }}
model name      : {{ index . "model name" }}
stepping        : {{ index . "stepping" }}
cpu MHz         : {{ index . "cpu MHz" }}
cache size      : {{ index . "cache size" }}
physical id     : {{ index . "physical id" }}
siblings        : {{ index . "siblings" }}
core id         : {{ index . "core id" }}
cpu cores       : {{ index . "cpu cores" }}
apicid          : {{ index . "apicid" }}
initial apicid  : {{ index . "initial apicid" }}
fpu             : {{ index . "fpu" }}
fpu_exception   : {{ index . "fpu_exception" }}
cpuid level     : {{ index . "cpuid level" }}
wp              : {{ index . "wp" }}
flags           : {{ index . "flags" }}
bugs            : {{ index . "bugs" }}
bogomips        : {{ index . "bogomips" }}
clflush size    : {{ index . "clflush size" }}
cache_alignment : {{ index . "cache_alignment" }}
address sizes   : {{ index . "address sizes" }}
power management:

`
