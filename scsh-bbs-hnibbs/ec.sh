#!/usr/bin/expect -f

# Set variables using Tcl
set script_path [file normalize [info script]]
set script_dir [file dirname $script_path]
set LABEL [lindex $argv 0]
set CURVE [lindex $argv 1]
set KUC [lindex $argv 2]
set UserPIN [lindex $argv 3]

# Change directory
cd $script_dir/../

set timeout -1

spawn ./scsh3

expect ">"

send "var LABEL='$LABEL'; var CURVE='$CURVE'; var KUC=$KUC; var UserPIN=$UserPIN;\r"
expect ">"

send "load(\"scsh-bbs-hnibbs/ec.js\");\r"

expect ">"

send "q\r"

expect "Shell closed."

expect eof
