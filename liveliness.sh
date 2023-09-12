#!/bin/bash

IFS=', '

read -r -a repos <<< "$LIVELINESS_REPOS"

for i in "${repos[@]}"
do
  echo "repo $i liveliness check..."
  response=$(curl --head -L -w '%{http_code}' -o /dev/null -s -k -x http://127.0.0.1:3128 "$i")
  if [[ "$response" -lt "200" ]] || [[ "$response" -ge "400" ]]; then
    echo "failed curl for repo $i"
    exit 1
  fi
done
