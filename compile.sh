#!/bin/bash

set -e

javac -d build src/main/burp/*.java
(cd build; jar cvf sourceMap.jar *)
