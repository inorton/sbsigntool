#!/bin/bash -ex

signed="test.signed"
reattached="test.reattached"
sig="test.sig"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
cp "$signed" "$reattached"
"$sbattach" --detach "$sig" --remove "$reattached"
"$sbattach" --attach "$sig" "$reattached"

# ensure we can verify the reattached signature
"$sbverify" --cert "$cert" "$reattached"

# ensure that the unsigned file is the same size as our original binary
[ $(stat --format=%s "$signed") -eq $(stat --format=%s "$reattached") ]

