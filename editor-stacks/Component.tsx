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

import { FC, useCallback, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';

import { StacksEditor } from '@stackoverflow/stacks-editor';

import '@stackoverflow/stacks';
import '@stackoverflow/stacks/dist/css/stacks.css';

import '@stackoverflow/stacks-editor/dist/styles.css';
import { createOnChangePlugin } from './onChange-plugin';

export interface EditorProps {
  value: string;
  onChange?: (value: string) => void;
  onFocus?: () => void;
  onBlur?: () => void;
  placeholder?: string;
  autoFocus?: boolean;
  imageUploadHandler?: (file: File | string) => Promise<string>;
  uploadConfig?: {
    maxImageSizeMiB?: number;
    allowedExtensions?: string[];
  };
}

const Component: FC<EditorProps> = ({
  value,
  onChange,
  onFocus,
  onBlur,
  placeholder = '',
  autoFocus = false,
  imageUploadHandler,
  uploadConfig,
}) => {
  const { t } = useTranslation('plugin', {
    keyPrefix: 'editor_stacks.frontend',
  });
  const containerRef = useRef<HTMLDivElement>(null);
  const editorInstanceRef = useRef<StacksEditor | null>(null);
  const isInitializedRef = useRef(false);
  const onChangeRef = useRef(onChange);
  const onFocusRef = useRef(onFocus);
  const onBlurRef = useRef(onBlur);
  const autoFocusTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );

  // Version compatibility temporarily disabled

  useEffect(() => {
    onChangeRef.current = onChange;
    onFocusRef.current = onFocus;
    onBlurRef.current = onBlur;
  });

  const syncTheme = useCallback(() => {
    if (!containerRef.current) return;

    containerRef.current?.classList.remove(
      'theme-light',
      'theme-dark',
      'theme-system',
    );
    const themeAttr =
      document.documentElement.getAttribute('data-bs-theme') ||
      document.body.getAttribute('data-bs-theme');

    if (themeAttr) {
      containerRef.current?.classList.add(`theme-${themeAttr}`);
    }
  }, []);

  useEffect(() => {
    syncTheme();
  }, [syncTheme]);

  useEffect(() => {
    const observer = new MutationObserver(() => {
      syncTheme();
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-bs-theme', 'class'],
    });
    observer.observe(document.body, {
      attributes: true,
      attributeFilter: ['data-bs-theme', 'class'],
    });
    return () => observer.disconnect();
  }, [syncTheme]);

  useEffect(() => {
    if (!containerRef.current || isInitializedRef.current) {
      return;
    }

    let editorInstance: StacksEditor | null = null;

    try {
      // Convert file extensions to MIME types for editor-stacks validation
      const extensionToMimeType = (ext: string): string => {
        const extension = ext.toLowerCase().replace(/^\./, '');
        const mimeTypeMap: Record<string, string> = {
          jpg: 'image/jpeg',
          jpeg: 'image/jpeg',
          png: 'image/png',
          gif: 'image/gif',
          webp: 'image/webp',
          svg: 'image/svg+xml',
          bmp: 'image/bmp',
          ico: 'image/x-icon',
          pdf: 'application/pdf',
          doc: 'application/msword',
          docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          xls: 'application/vnd.ms-excel',
          xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          ppt: 'application/vnd.ms-powerpoint',
          pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
          zip: 'application/zip',
          rar: 'application/x-rar-compressed',
          txt: 'text/plain',
          csv: 'text/csv',
        };
        return mimeTypeMap[extension] || ext;
      };

      const allowedFileTypes = uploadConfig?.allowedExtensions
        ? uploadConfig.allowedExtensions.map(extensionToMimeType)
        : undefined;

      editorInstance = new StacksEditor(containerRef.current, value || '', {
        placeholderText: placeholder || t('placeholder', ''),
        parserFeatures: {
          tables: true,
          html: false,
        },
        imageUpload: imageUploadHandler
          ? {
              handler: imageUploadHandler,
              sizeLimitMib: uploadConfig?.maxImageSizeMiB,
              acceptedFileTypes: allowedFileTypes,
            }
          : undefined,
        editorHelpLink: 'https://stackoverflow.com/editing-help',
        editorPlugins: onChange
          ? [
              createOnChangePlugin(
                () => editorInstanceRef.current,
                (content: string) => {
                  onChangeRef.current?.(content);
                }
              ),
            ]
          : [],
      });

      editorInstanceRef.current = editorInstance;
      isInitializedRef.current = true;

      const editor = editorInstance;
      const editorElement = editor.dom as HTMLElement;
      const handleFocus = () => onFocusRef.current?.();
      const handleBlur = () => onBlurRef.current?.();

      if (editorElement) {
        editorElement.addEventListener('focus', handleFocus, true);
        editorElement.addEventListener('blur', handleBlur, true);
      }

      if (autoFocus) {
        autoFocusTimeoutRef.current = setTimeout(() => {
          if (editor) {
            editor.focus();
          }
        }, 100);
      }

      return () => {
        if (autoFocusTimeoutRef.current) {
          clearTimeout(autoFocusTimeoutRef.current);
          autoFocusTimeoutRef.current = null;
        }

        if (editorElement) {
          editorElement.removeEventListener('focus', handleFocus, true);
          editorElement.removeEventListener('blur', handleBlur, true);
        }

        if (editorInstance) {
          try {
            editorInstance.destroy();
          } catch (e) {
            console.error('Error destroying editor:', e);
          }
        }

        editorInstanceRef.current = null;
        isInitializedRef.current = false;

        if (containerRef.current) {
          containerRef.current.innerHTML = '';
        }
      };
    } catch (error) {
      console.error('Failed to initialize Stacks Editor:', error);
      isInitializedRef.current = false;
    }
  }, []);

  useEffect(() => {
    const editor = editorInstanceRef.current;
    if (!editor || !isInitializedRef.current) {
      return;
    }

    try {
      if (editor.content !== value) {
        editor.content = value;
      }
    } catch (error) {
      console.error('Error syncing editor content:', error);
    }
  }, [value]);

  return (
    <>
      <style>{`
        /* Hide specific menu buttons */
        .editor-stacks-wrapper [data-key="tag-btn"],
        .editor-stacks-wrapper [data-key="meta-tag-btn"],
        .editor-stacks-wrapper [data-key="spoiler-btn"],
        .editor-stacks-wrapper [data-key="subscript-btn"],
        .editor-stacks-wrapper [data-key="superscript-btn"] {
          display: none !important;
        }
      `}</style>
      <div
        className="editor-stacks-wrapper editor-stacks-scope"
        ref={containerRef}
      />
    </>
  );
};

export default Component;
