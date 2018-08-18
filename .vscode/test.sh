#!/bin/bash

MALICE_TIMEOUT=100

for filename in .; do
    maice scan "$filename"
done