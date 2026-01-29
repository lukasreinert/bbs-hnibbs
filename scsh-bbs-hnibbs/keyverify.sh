#!/usr/bin/expect -f

# Set variables using Tcl
set script_path [file normalize [info script]]
set script_dir [file dirname $script_path]

# Change directory
cd $script_dir/../

set timeout -1

spawn ./scsh3

expect ">"

send "load(\"scsh-bbs-hnibbs/keyverify.js\");\r"

expect ">"

send "q\r"

expect "Shell closed."

expect eof
