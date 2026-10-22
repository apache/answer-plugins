#!/bin/bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

project_root="."

for dir in $(find "$project_root" -type d); do
    if [[ "$dir" == *node_modules* ]] || [[ "$dir" == *.git* ]] || [[ "$dir" == *.vscode* ]]; then
        continue
    fi

    if [ -f "$dir/info.yaml" ]; then
        version=$(awk '/version:/{print $2}' "$dir/info.yaml")

        if [ -f "$dir/package.json" ]; then
            jq --arg version "$version" '.version = $version' "$dir/package.json" >"$dir/package.json.tmp"
            mv "$dir/package.json.tmp" "$dir/package.json"
        fi
    fi
done

echo "{}" >"$project_root/plugins_desc.json"

plugins=()
for dir in "$project_root"/*/; do
    if [[ "$dir" =~ (node_modules|util|script|.git|.vscode) ]]; then
        continue
    fi
    plugins+=($(basename "$dir"))
done

plugins=($(printf '%s\n' "${plugins[@]}" | sort))

for plugin in "${plugins[@]}"; do
    slug_name=""
    link=""
    dir="$project_root/$plugin"
    if [ -f "$dir/info.yaml" ]; then
        slug_name=$(yq '.slug_name' "$dir/info.yaml")
        link=$(yq '.link' "$dir/info.yaml")
    fi

    if [ -d "$dir/i18n" ]; then
        for file in $(find "$dir/i18n" -type f -name "*.yaml" | LC_ALL=C sort); do
            if [ -f "$file" ]; then
                file_name=$(basename "$file")
                file_name=${file_name%.*}

                if [ -f "$file" ]; then
                    name=$(yq ".plugin.${slug_name}.backend.info.name.other" "$file")
                    description=$(yq ".plugin.${slug_name}.backend.info.description.other" "$file")

                    if [ "$name" == "null" ] || [ "$description" == "null" ]; then
                        continue
                    fi

                    if [ -f "$project_root/plugins_desc.json" ]; then
                        if [ "$(jq ".$file_name" "$project_root/plugins_desc.json")" != "null" ]; then
                            jq ".$file_name += [{\"name\": \"$name\", \"desc\": \"$description\", \"link\": \"$link\"}]" "$project_root/plugins_desc.json" >"$project_root/plugins_desc.json.tmp"
                            mv "$project_root/plugins_desc.json.tmp" "$project_root/plugins_desc.json"
                        else
                            jq ".$file_name = [{\"name\": \"$name\", \"desc\": \"$description\", \"link\": \"$link\"}]" "$project_root/plugins_desc.json" >"$project_root/plugins_desc.json.tmp"
                            mv "$project_root/plugins_desc.json.tmp" "$project_root/plugins_desc.json"
                        fi
                    fi
                fi
            fi
        done
    fi
done
