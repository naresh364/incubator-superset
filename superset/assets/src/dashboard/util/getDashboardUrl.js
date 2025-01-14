/**
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
/* eslint camelcase: 0 */

export default function getDashboardUrl(pathname, filters = {}, hash = '', stand_alone = false) {
  const preselect_filters = encodeURIComponent(JSON.stringify(filters));
  const hashSection = hash ? `#${hash}` : '';
  const sa = stand_alone ? '&standalone=true' : ''
  return `${pathname}?preselect_filters=${preselect_filters}${sa}${hashSection}`;
}

