// Package meanziphra отдаёт файлы, вшитые в бинарник mz: конфиг релиза, его входные данные и шаблоны скриптов.
package meanziphra

import (
	"embed"
	"io/fs"
)

// ReleaseConfig — имя конфига релиза в Inputs.
const ReleaseConfig = "config.release.yaml"

// Inputs содержит ReleaseConfig и файлы, которые он читает при выпуске сертификатов.
//
//go:embed config.release.yaml inputs/russian-trusted-root-ca.pem inputs/categories.tpl inputs/categories
var Inputs embed.FS

//go:embed scripts/*.tpl
var scripts embed.FS

// Scripts возвращает шаблоны скриптов установки и удаления.
func Scripts() fs.FS {
	sub, err := fs.Sub(scripts, "scripts")
	if err != nil {
		panic(err)
	}
	return sub
}
