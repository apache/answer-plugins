/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { Plugin } from "prosemirror-state";
import type { EditorPlugin, StacksEditor } from "@stackoverflow/stacks-editor";

/**
 * Creates a StacksEditor plugin that listens to content changes.
 * This is the official recommended approach for monitoring editor updates.
 * Reference: https://discuss.prosemirror.net/t/how-to-get-data-from-the-editor/3263/5
 *
 * Works in both RichText and Markdown modes automatically.
 *
 * @param getEditor Function that returns the StacksEditor instance
 * @param onUpdate Callback function that receives the updated editor content
 * @returns A StacksEditor EditorPlugin
 */
export const createOnChangePlugin = (
  getEditor: () => StacksEditor | null,
  onUpdate: (content: string) => void
): EditorPlugin => {
  return () => {
    let lastContent = "";

    const proseMirrorPlugin: any = new Plugin({
      view() {
        return {
          update() {
            try {
              // Get the editor instance to access serialized markdown content
              const editor = getEditor();
              if (!editor) return;

              // Use editor.content to get properly serialized markdown
              const content = editor.content;

              // Only trigger callback if content actually changed
              if (content !== lastContent) {
                lastContent = content;
                onUpdate(content);
              }
            } catch (error) {
              console.error("Error getting editor content:", error);
            }
          },
        };
      },
    });

    return {
      richText: {
        plugins: [proseMirrorPlugin],
      },
      commonmark: {
        plugins: [proseMirrorPlugin],
      },
    };
  };
};
