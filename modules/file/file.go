/*
 Reeve - File Module

 Copyright 2015 Evan Borgstrom

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package file

import (
	log "github.com/Sirupsen/logrus"

	"github.com/borgstrom/reeve/modules"
)

func init() {
	modules.Register("file", modules.ModuleFunctions{
		"chown": Chown,
	})
}

func Chown(path string, mode int) (bool, error) {
	log.WithFields(log.Fields{
		"path": path,
		"mode": mode,
	}).Debug("Chown")

	return true, nil
}
