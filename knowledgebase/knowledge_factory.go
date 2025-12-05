// Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package knowledgebase

import "errors"

type Config struct {
	Name          string
	Description   string
	BackendType   KnowledgeBackendType
	BackendConfig map[string]any
	TopK          int
	AppName       string
	Index         string
}

func BuildKnowledgeBase(cfg Config) (*Knowledge, error) {
	switch cfg.BackendType {
	case VikingBackend:
		return NewInMemoryKnowledgeBackend(kb.Index)
	default:
		return nil, errors.New("Unsupported knowledge backend: " + string(cfg.BackendType))
	}
}
