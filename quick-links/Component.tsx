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
import { useTranslation } from 'react-i18next';
import useSWR from 'swr'

const Component = ({ navigate, request }) => {

  const { t } = useTranslation('plugin', {
    keyPrefix: 'quick_links.frontend',
  });

  const { data } = useSWR(
    ['/answer/api/v1/sidebar/config'],
    request.instance.get,
  );
  const tags = data?.tags || [];
  const links = data?.links_text?.split('\n') || [];

  const handleNavigate = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const url = e.currentTarget.getAttribute('href');
    if (!url || url.trim() === '') return;

    if (url.startsWith('/')) {
      navigate(url);
    } else if (/^https?:\/\//.test(url)) {
      window.open(url, '_blank', 'noopener,noreferrer');
    } else {
      console.warn('Ignoring potentially unsafe URL:', url);
    }
  }

  if (!tags.length && !links.length) {
    return
  }

  return (
    <div>
      <div className="py-2 px-3 mt-3 small fw-bold quick-link">{t('quick_links')}</div>
      {tags?.map((tag) => {
        const href = `/tags/${encodeURIComponent(tag.slug_name)}`
        return (
          <a
            href={href}
            className={`nav-link ${window.location.pathname === href ? 'active' : ''}`}
            onClick={handleNavigate}>
            <span>{tag.display_name}</span>
          </a>
        )
      })}

      {links?.map((link) => {
        const name = link.split(',')[0]
        const url = link.split(',')[1]?.trim()
        if (!url || !name) {
          return null;
        }
        return (
          <a
            href={url}
            className={`nav-link ${window.location.pathname === url ? 'active' : ''}`}
            onClick={handleNavigate}
          >
            <span>{name}</span>
          </a>
        )
      })}
    </div>
  );
};

export default Component;
