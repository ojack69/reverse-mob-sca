#!/bin/bash

base_path="$1"

if [[ -z "$base_path" ]]
then
    base_path='./'
fi

function extract(){
    plists=$(find "$base_path" -name "Info.plist" 2>/dev/null)
    for plist in $plists; do
        bundle_identifier=$(plutil -p $plist | grep -i "CFBundleIdentifier" | cut -d '"' -f 4)
        bundle_name=$(plutil -p $plist | grep -i "CFBundleName" | cut -d '"' -f 4)
        version=$(plutil -p $plist | grep -i "CFBundleShortVersionString" | cut -d '"' -f 4)
        
        if [[ -n "$bundle_name" ]] && [[ -n "$version" ]]
        then
            echo "$bundle_name@$version@$bundle_identifier"
        fi
    done
}

extract | sort | uniq
